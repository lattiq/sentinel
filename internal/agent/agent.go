package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	awsClient "github.com/lattiq/sentinel/internal/aws"
	"github.com/lattiq/sentinel/internal/collector/cloudtrail"
	"github.com/lattiq/sentinel/internal/collector/health"
	"github.com/lattiq/sentinel/internal/collector/querylogs"
	"github.com/lattiq/sentinel/internal/collector/rds"
	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/internal/processor"
	"github.com/lattiq/sentinel/internal/transmitter"
	"github.com/lattiq/sentinel/pkg/types"
)

// Agent represents the main Sentinel monitoring agent
type Agent struct {
	config      *config.Config
	logger      *logrus.Entry
	awsClient   *awsClient.ClientManager
	collectors  []types.Collector
	processor   *processor.EventProcessor
	transmitter *transmitter.HTTPTransmitter

	// Event pipeline
	eventChan     chan types.Event
	processedChan chan []types.MonitoringMessage

	// Control
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	healthData types.HealthData

	// Configuration tracking
	configMutex    sync.RWMutex
	previousConfig *config.Config
	configHash     string
	configVersion  string
	configPushed   bool
}

// New creates a new monitoring agent
func New(cfg *config.Config) (*Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger := logrus.WithField("component", "agent")

	// Create AWS client manager
	awsClient, err := awsClient.NewClientManager(cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create AWS client: %w", err)
	}

	// Create event processor
	eventProcessor, err := processor.New(cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create event processor: %w", err)
	}

	// Create HTTP transmitter
	httpTransmitter, err := transmitter.NewHTTPTransmitter(&cfg.Hub)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create HTTP transmitter: %w", err)
	}

	agent := &Agent{
		config:        cfg,
		logger:        logger,
		awsClient:     awsClient,
		processor:     eventProcessor,
		transmitter:   httpTransmitter,
		eventChan:     make(chan types.Event, 1000),
		processedChan: make(chan []types.MonitoringMessage, 100),
		ctx:           ctx,
		cancel:        cancel,
		healthData:    types.HealthData{},
	}

	// Initialize collectors
	if err := agent.initializeCollectors(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize collectors: %w", err)
	}

	logger.Info("Agent created successfully")
	return agent, nil
}

// Start starts the monitoring agent
func (a *Agent) Start() error {
	a.logger.Info("Starting sentinel agent")

	// Start event processing pipeline
	a.wg.Add(1)
	go a.runEventProcessor()

	// Start transmission pipeline
	a.wg.Add(1)
	go a.runTransmissionPipeline()

	// Start health monitoring
	a.wg.Add(1)
	go a.runHealthMonitor()

	// Start configuration tracking
	a.StartConfigurationTracking()

	// Start all collectors
	for _, collector := range a.collectors {
		a.wg.Add(1)
		go a.runCollector(collector)
	}

	a.logger.Info("Agent started successfully")
	return nil
}

// runEventProcessor processes events from collectors
func (a *Agent) runEventProcessor() {
	defer a.wg.Done()

	batch := make([]types.Event, 0, a.config.Batch.MaxSize)
	batchTimer := time.NewTimer(a.config.Batch.MaxAge)
	defer batchTimer.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Event processor stopping")
			// Process any remaining events
			if len(batch) > 0 {
				a.processBatch(batch)
			}
			return

		case event := <-a.eventChan:
			batch = append(batch, event)

			// Check if batch is full
			if len(batch) >= a.config.Batch.MaxSize {
				a.processBatch(batch)
				batch = batch[:0]
				batchTimer.Reset(a.config.Batch.MaxAge)
			}

		case <-batchTimer.C:
			// Process batch on timeout
			if len(batch) > 0 {
				a.processBatch(batch)
				batch = batch[:0]
			}
			batchTimer.Reset(a.config.Batch.MaxAge)
		}
	}
}

// processBatch processes a batch of events
func (a *Agent) processBatch(events []types.Event) {
	if len(events) == 0 {
		return
	}

	messages, err := a.processor.Process(a.ctx, events)
	if err != nil {
		a.logger.WithError(err).Error("Failed to process event batch")
		return
	}

	if len(messages) > 0 {
		select {
		case a.processedChan <- messages:
			a.logger.WithField("message_count", len(messages)).Debug("Processed messages queued for transmission")
		default:
			a.logger.Warn("Processed message channel full, dropping messages")
		}
	}
}

// runTransmissionPipeline handles transmission of processed messages
func (a *Agent) runTransmissionPipeline() {
	defer a.wg.Done()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Transmission pipeline stopping")
			return

		case messages := <-a.processedChan:
			if err := a.transmitter.Send(a.ctx, messages); err != nil {
				a.logger.WithError(err).WithField("message_count", len(messages)).Error("Failed to transmit messages")
			} else {
				a.logger.WithField("message_count", len(messages)).Debug("Messages transmitted successfully")
			}
		}
	}
}

// runHealthMonitor monitors agent health
func (a *Agent) runHealthMonitor() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.Health.ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Health monitor stopping")
			return

		case <-ticker.C:
			// Update health data
			a.updateHealthData()

			// Create health event
			healthEvent := types.Event{
				ID:        fmt.Sprintf("health-%d", time.Now().Unix()),
				Type:      types.EventTypeAgentHealth,
				Timestamp: time.Now(),
				Source:    "agent_health",
				AgentHealth: &types.AgentHealthEvent{
					AgentVersion:    "1.0.0",
					Status:          "healthy",
					UptimeSeconds:   int64(time.Since(time.Now()).Seconds()),
					CollectorStates: a.getCollectorStates(),
					SystemMetrics:   a.getSystemMetrics(),
					ErrorCount:      a.healthData.ErrorCount,
					Timestamp:       time.Now().Unix(),
				},
			}

			// Send health event through normal pipeline
			select {
			case a.eventChan <- healthEvent:
			default:
				a.logger.Warn("Event channel full, dropping health event")
			}
		}
	}
}

// updateHealthData updates internal health metrics
func (a *Agent) updateHealthData() {
	// This would collect actual system metrics in production
	a.healthData.LastUpdate = time.Now()
}

// getCollectorStates returns the current state of all collectors
func (a *Agent) getCollectorStates() map[string]string {
	states := make(map[string]string)
	for _, collector := range a.collectors {
		states[collector.Name()] = "running" // Simplified
	}
	return states
}

// getSystemMetrics returns current system metrics
func (a *Agent) getSystemMetrics() types.SystemMetrics {
	return types.SystemMetrics{
		MemoryUsageMB:  0,   // Would be populated with actual metrics
		CPUPercent:     0.0, // Would be populated with actual metrics
		DiskUsageMB:    0,   // Would be populated with actual metrics
		GoroutineCount: 0,   // Would be populated with actual metrics
	}
}

// GetMetrics returns comprehensive agent metrics
func (a *Agent) GetMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"agent": map[string]interface{}{
			"uptime_seconds": time.Since(a.healthData.LastUpdate).Seconds(),
			"collectors":     len(a.collectors),
			"health":         a.healthData,
		},
		"processor":   a.processor.GetMetrics(),
		"transmitter": a.transmitter.GetMetrics(),
	}

	// Add collector-specific metrics
	collectorMetrics := make(map[string]interface{})
	for _, collector := range a.collectors {
		if metricsProvider, ok := collector.(types.MetricsProvider); ok {
			collectorMetrics[collector.Name()] = metricsProvider.GetMetrics()
		}
	}
	metrics["collectors"] = collectorMetrics

	return metrics
}

// runCollector runs a single collector
func (a *Agent) runCollector(collector types.Collector) {
	defer a.wg.Done()

	// a.logger.WithField("collector", collector.Name()).Info("Starting collector")

	// Start the collector
	if err := collector.Start(a.ctx); err != nil {
		a.logger.WithError(err).WithField("collector", collector.Name()).Error("Failed to start collector")
		return
	}

	// Subscribe to collector events
	eventsChan := collector.Subscribe()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.WithField("collector", collector.Name()).Info("Collector stopping")
			if err := collector.Stop(a.ctx); err != nil {
				a.logger.WithError(err).WithField("collector", collector.Name()).Error("Error stopping collector")
			}
			return

		case event := <-eventsChan:
			select {
			case a.eventChan <- event:
				// Event sent successfully
			default:
				a.logger.WithField("collector", collector.Name()).Warn("Event channel full, dropping event")
			}
		}
	}
}

// initializeCollectors initializes all enabled collectors
func (a *Agent) initializeCollectors() error {
	// Initialize Query Logs Collector
	if a.config.DataSources.QueryLogs.Enabled {
		collector, err := querylogs.New(
			&a.config.DataSources.QueryLogs,
			a.awsClient,
			a.config.GetFeatureColumns(),
		)
		if err != nil {
			return fmt.Errorf("failed to create query logs collector: %w", err)
		}
		a.collectors = append(a.collectors, collector)
		a.logger.Info("Query logs collector initialized")
	}

	// Initialize RDS collectors
	if a.config.DataSources.RDS.Enabled {
		// RDS instances collector
		instancesCollector, err := rds.NewInstancesCollector(&a.config.DataSources.RDS, a.awsClient)
		if err != nil {
			return fmt.Errorf("failed to create RDS instances collector: %w", err)
		}
		a.collectors = append(a.collectors, instancesCollector)
		a.logger.Info("RDS instances collector initialized")

		// RDS snapshots collector
		snapshotsCollector, err := rds.NewSnapshotsCollector(&a.config.DataSources.RDS, a.awsClient)
		if err != nil {
			return fmt.Errorf("failed to create RDS snapshots collector: %w", err)
		}
		a.collectors = append(a.collectors, snapshotsCollector)
		a.logger.Info("RDS snapshots collector initialized")

		// RDS config collector
		configCollector, err := rds.NewConfigCollector(&a.config.DataSources.RDS, a.awsClient)
		if err != nil {
			return fmt.Errorf("failed to create RDS config collector: %w", err)
		}
		a.collectors = append(a.collectors, configCollector)
		a.logger.Info("RDS config collector initialized")
	}

	// Initialize CloudTrail collector
	if a.config.DataSources.CloudTrail.Enabled {
		cloudTrailCollector, err := cloudtrail.NewCollector(&a.config.DataSources.CloudTrail, a.awsClient)
		if err != nil {
			return fmt.Errorf("failed to create CloudTrail collector: %w", err)
		}
		a.collectors = append(a.collectors, cloudTrailCollector)
		a.logger.Info("CloudTrail collector initialized")
	}

	// Initialize Health collector (always enabled if health monitoring is enabled)
	if a.config.Health.Enabled {
		healthCollector, err := health.NewCollector(a.config, a.awsClient)
		if err != nil {
			return fmt.Errorf("failed to create health collector: %w", err)
		}
		a.collectors = append(a.collectors, healthCollector)
		a.logger.Info("Health collector initialized")
	}

	a.logger.WithField("collector_count", len(a.collectors)).Info("All collectors initialized")
	return nil
}

// Stop gracefully stops the agent
func (a *Agent) Stop() error {
	a.logger.Info("Stopping sentinel agent")

	// Cancel context to stop all goroutines
	a.cancel()

	// Wait for all goroutines to finish
	a.wg.Wait()

	a.logger.Info("Agent stopped successfully")
	return nil
}

// PushConfiguration pushes current configuration to the hub service
func (a *Agent) PushConfiguration() error {
	a.configMutex.Lock()
	defer a.configMutex.Unlock()

	currentHash := a.config.Hash()

	// Detect changes if we have a previous config
	var changedSections []string
	var err error
	if a.previousConfig != nil {
		changedSections, err = a.config.DetectChanges(a.previousConfig, a.configHash)
		if err != nil {
			return fmt.Errorf("failed to detect config changes: %w", err)
		}
	} else {
		changedSections = []string{"initial_config"}
	}

	// Only push if there are changes or if we haven't pushed yet
	if len(changedSections) == 0 && a.configPushed {
		a.logger.Debug("No configuration changes detected, skipping push")
		return nil
	}

	// Create config event
	configEvent := types.Event{
		ID:        fmt.Sprintf("config-%s-%d", a.config.Client.ID, time.Now().Unix()),
		Type:      types.EventTypeConfig,
		Timestamp: time.Now(),
		Source:    "agent_config",
		Config: &types.ConfigEvent{
			ClientID:        a.config.Client.ID,
			ClientName:      a.config.Client.Name,
			Environment:     a.config.Client.Environment,
			ConfigVersion:   a.getConfigVersion(),
			ConfigHash:      currentHash,
			PreviousHash:    a.configHash,
			ChangedSections: changedSections,
			Configuration:   a.config,
			Timestamp:       time.Now().Unix(),
			Metadata: map[string]interface{}{
				"pushed_at":     time.Now().Format(time.RFC3339),
				"agent_version": "1.0.0",
			},
		},
	}

	// Send config event through normal pipeline
	select {
	case a.eventChan <- configEvent:
		a.logger.WithFields(logrus.Fields{
			"config_hash":      currentHash,
			"changed_sections": changedSections,
		}).Info("Configuration pushed to hub")

		// Update tracking fields
		a.previousConfig = a.deepCopyConfig(a.config)
		a.configHash = currentHash
		a.configPushed = true

		return nil
	default:
		return fmt.Errorf("event channel full, unable to push configuration")
	}
}

// StartConfigurationTracking starts periodic configuration tracking
func (a *Agent) StartConfigurationTracking() {
	if !a.config.Health.Enabled {
		a.logger.Info("Health monitoring disabled, skipping configuration tracking")
		return
	}

	a.wg.Add(1)
	go a.runConfigurationTracker()
}

// runConfigurationTracker runs the configuration tracking loop
func (a *Agent) runConfigurationTracker() {
	defer a.wg.Done()

	// Initial config push
	if err := a.PushConfiguration(); err != nil {
		a.logger.WithError(err).Error("Failed to push initial configuration")
	}

	// Setup periodic config check (every 5 minutes)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Configuration tracker stopping")
			return

		case <-ticker.C:
			if err := a.PushConfiguration(); err != nil {
				a.logger.WithError(err).Error("Failed to push configuration update")
			}
		}
	}
}

// getConfigVersion generates a version string for the configuration
func (a *Agent) getConfigVersion() string {
	if a.configVersion == "" {
		a.configVersion = fmt.Sprintf("v1.0.0-%d", time.Now().Unix())
	}
	return a.configVersion
}

// deepCopyConfig creates a deep copy of the configuration
func (a *Agent) deepCopyConfig(cfg *config.Config) *config.Config {
	// This is a simplified deep copy - in production, you might want to use a proper deep copy library
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		a.logger.WithError(err).Error("Failed to marshal config for deep copy")
		return nil
	}

	var newConfig config.Config
	if err := json.Unmarshal(configBytes, &newConfig); err != nil {
		a.logger.WithError(err).Error("Failed to unmarshal config for deep copy")
		return nil
	}

	return &newConfig
}
