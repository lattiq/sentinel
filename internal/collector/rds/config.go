package rds

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/sirupsen/logrus"

	awsClient "github.com/lattiq/sentinel/internal/aws"
	"github.com/lattiq/sentinel/internal/config"
	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

// ConfigCollector implements RDS configuration monitoring
type ConfigCollector struct {
	config     *config.RDSConfig
	awsManager *awsClient.ClientManager
	logger     *logrus.Entry

	// State management
	mu        sync.RWMutex
	running   bool
	startTime time.Time

	// Event distribution
	eventsChan  chan sentinelTypes.Event
	subscribers []chan sentinelTypes.Event

	// Health metrics
	health          sentinelTypes.CollectorHealth
	eventsCollected int64
	errorsCount     int64
	lastError       string

	// Configuration tracking for change detection
	lastConfigs map[string]map[string]types.Parameter // instanceID -> parameterName -> Parameter
}

// NewConfigCollector creates a new RDS configuration collector
func NewConfigCollector(cfg *config.RDSConfig, awsManager *awsClient.ClientManager) (*ConfigCollector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if awsManager == nil {
		return nil, fmt.Errorf("AWS manager is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component":             "rds_config_collector",
		"monitor_all_instances": cfg.MonitorAllInstances,
		"poll_interval":         cfg.PollIntervals.Config,
	})

	collector := &ConfigCollector{
		config:      cfg,
		awsManager:  awsManager,
		logger:      logger,
		eventsChan:  make(chan sentinelTypes.Event, 1000),
		subscribers: make([]chan sentinelTypes.Event, 0),
		lastConfigs: make(map[string]map[string]types.Parameter),
		health: sentinelTypes.CollectorHealth{
			Status:      string(sentinelTypes.HealthStatusStopped),
			Performance: sentinelTypes.PerformanceStats{},
		},
	}

	logger.Info("RDS config collector created")
	return collector, nil
}

// Name returns the collector name
func (c *ConfigCollector) Name() string {
	return "rds_config"
}

// Start begins the RDS configuration monitoring process
func (c *ConfigCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector is already running")
	}

	c.logger.Info("Starting RDS config collector")
	c.running = true
	c.startTime = time.Now()
	c.health.Status = string(sentinelTypes.HealthStatusHealthy)
	c.health.LastCollection = time.Now()

	// Start collection goroutine
	go c.collectLoop(ctx)

	// Start event distribution goroutine
	go c.distributeEvents(ctx)

	c.logger.Info("RDS config collector started successfully")
	return nil
}

// Stop gracefully stops the collector
func (c *ConfigCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.logger.Info("Stopping RDS config collector")
	c.running = false
	c.health.Status = string(sentinelTypes.HealthStatusStopped)

	// Close events channel
	close(c.eventsChan)

	c.logger.Info("RDS config collector stopped")
	return nil
}

// Collect performs a single collection cycle (for manual triggering)
func (c *ConfigCollector) Collect(ctx context.Context) ([]sentinelTypes.Event, error) {
	if !c.config.Enabled {
		return nil, nil
	}

	startTime := time.Now()
	events, err := c.fetchConfigEvents(ctx)
	duration := time.Since(startTime)

	// Update health metrics
	c.mu.Lock()
	c.health.LastCollection = time.Now()
	c.health.Performance.AvgLatency = duration

	if err != nil {
		c.errorsCount++
		c.lastError = err.Error()
		c.health.Status = string(sentinelTypes.HealthStatusDegraded)
		c.mu.Unlock()
		return nil, err
	} else {
		c.eventsCollected += int64(len(events))
		c.health.EventsCollected = c.eventsCollected
		c.health.ErrorsCount = c.errorsCount
		if c.health.Status == string(sentinelTypes.HealthStatusDegraded) {
			c.health.Status = string(sentinelTypes.HealthStatusHealthy)
		}
	}
	c.mu.Unlock()

	return events, nil
}

// Health returns the current health status
func (c *ConfigCollector) Health() sentinelTypes.CollectorHealth {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Update performance stats
	if c.running && !c.startTime.IsZero() {
		uptime := time.Since(c.startTime)
		if c.eventsCollected > 0 {
			c.health.Performance.Throughput = float64(c.eventsCollected) / uptime.Seconds()
		}
		if c.errorsCount > 0 && c.eventsCollected > 0 {
			c.health.Performance.SuccessRate = float64(c.eventsCollected-c.errorsCount) / float64(c.eventsCollected) * 100
		} else {
			c.health.Performance.SuccessRate = 100.0
		}
	}

	return c.health
}

// Subscribe returns a channel for real-time events
func (c *ConfigCollector) Subscribe() <-chan sentinelTypes.Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	eventChan := make(chan sentinelTypes.Event, 100)
	c.subscribers = append(c.subscribers, eventChan)
	return eventChan
}

// collectLoop runs the periodic collection process
func (c *ConfigCollector) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.PollIntervals.Config)
	defer ticker.Stop()

	// Initial collection
	if events, err := c.Collect(ctx); err == nil {
		for _, event := range events {
			select {
			case c.eventsChan <- event:
			case <-ctx.Done():
				return
			default:
				c.logger.Warn("Events channel buffer full, dropping event")
			}
		}
	} else {
		c.logger.WithError(err).Error("Initial RDS config collection failed")
	}

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("RDS config collection loop stopping")
			return
		case <-ticker.C:
			if !c.isRunning() {
				return
			}

			events, err := c.Collect(ctx)
			if err != nil {
				c.logger.WithError(err).Error("Failed to collect RDS config")
				continue
			}

			// Send events to subscribers
			for _, event := range events {
				select {
				case c.eventsChan <- event:
				case <-ctx.Done():
					return
				default:
					c.logger.Warn("Events channel buffer full, dropping event")
				}
			}
		}
	}
}

// distributeEvents distributes events to all subscribers
func (c *ConfigCollector) distributeEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("RDS config event distribution stopping")
			// Close all subscriber channels
			c.mu.Lock()
			for _, ch := range c.subscribers {
				close(ch)
			}
			c.subscribers = c.subscribers[:0]
			c.mu.Unlock()
			return
		case event, ok := <-c.eventsChan:
			if !ok {
				// Events channel closed
				return
			}

			// Distribute to all subscribers
			c.mu.RLock()
			for i, ch := range c.subscribers {
				select {
				case ch <- event:
				default:
					c.logger.WithField("subscriber_index", i).Warn("Subscriber channel full, dropping event")
				}
			}
			c.mu.RUnlock()
		}
	}
}

// fetchConfigEvents retrieves and processes RDS configuration events
func (c *ConfigCollector) fetchConfigEvents(ctx context.Context) ([]sentinelTypes.Event, error) {
	rdsClient, err := c.awsManager.GetRDSClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS client: %w", err)
	}

	var events []sentinelTypes.Event

	// Get list of instances to monitor
	instances, err := c.getInstancesToMonitor(ctx, rdsClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get instances to monitor: %w", err)
	}

	// Monitor parameter groups for each instance
	for _, instance := range instances {
		instanceEvents, err := c.monitorInstanceConfig(ctx, rdsClient, instance)
		if err != nil {
			c.logger.WithError(err).WithField("instance", aws.ToString(instance.DBInstanceIdentifier)).Error("Failed to monitor instance config")
			continue
		}
		events = append(events, instanceEvents...)
	}

	return events, nil
}

// getInstancesToMonitor returns the list of DB instances to monitor
func (c *ConfigCollector) getInstancesToMonitor(ctx context.Context, rdsClient *rds.Client) ([]types.DBInstance, error) {
	var instances []types.DBInstance
	var marker *string

	for {
		input := &rds.DescribeDBInstancesInput{Marker: marker}
		result, err := rdsClient.DescribeDBInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB instances: %w", err)
		}

		for _, instance := range result.DBInstances {
			// Filter by configured instances if needed
			if !c.config.MonitorAllInstances && len(c.config.Instances) > 0 {
				instanceID := aws.ToString(instance.DBInstanceIdentifier)
				if !c.containsInstance(instanceID) {
					continue
				}
			}
			instances = append(instances, instance)
		}

		// Check if there are more results
		if result.Marker == nil || *result.Marker == "" {
			break
		}
		marker = result.Marker
	}

	return instances, nil
}

// monitorInstanceConfig monitors configuration for a specific instance
func (c *ConfigCollector) monitorInstanceConfig(ctx context.Context, rdsClient *rds.Client, instance types.DBInstance) ([]sentinelTypes.Event, error) {
	instanceID := aws.ToString(instance.DBInstanceIdentifier)

	// Get current parameter group
	var parameterGroupName string
	if len(instance.DBParameterGroups) > 0 {
		parameterGroupName = aws.ToString(instance.DBParameterGroups[0].DBParameterGroupName)
	} else {
		c.logger.WithField("instance", instanceID).Debug("No parameter group found for instance")
		return nil, nil
	}

	// Get parameters for the parameter group
	parameters, err := c.getParameterGroupParameters(ctx, rdsClient, parameterGroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to get parameters for group %s: %w", parameterGroupName, err)
	}

	// Check for changes
	events := c.detectConfigChanges(instanceID, parameterGroupName, parameters)

	return events, nil
}

// getParameterGroupParameters retrieves all parameters for a parameter group
func (c *ConfigCollector) getParameterGroupParameters(ctx context.Context, rdsClient *rds.Client, parameterGroupName string) (map[string]types.Parameter, error) {
	parameters := make(map[string]types.Parameter)
	var marker *string

	for {
		input := &rds.DescribeDBParametersInput{
			DBParameterGroupName: aws.String(parameterGroupName),
			Marker:               marker,
		}

		result, err := rdsClient.DescribeDBParameters(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB parameters: %w", err)
		}

		for _, param := range result.Parameters {
			if param.ParameterName != nil {
				parameters[*param.ParameterName] = param
			}
		}

		// Check if there are more results
		if result.Marker == nil || *result.Marker == "" {
			break
		}
		marker = result.Marker
	}

	return parameters, nil
}

// detectConfigChanges detects configuration changes and generates events
func (c *ConfigCollector) detectConfigChanges(instanceID, parameterGroupName string, currentParams map[string]types.Parameter) []sentinelTypes.Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	lastParams, exists := c.lastConfigs[instanceID]
	c.lastConfigs[instanceID] = currentParams

	var parameterChanges []sentinelTypes.ParameterChange
	var configParams []sentinelTypes.ConfigParameter

	// Build config parameters list
	for paramName, currentParam := range currentParams {
		configParam := sentinelTypes.ConfigParameter{
			Name:         aws.ToString(currentParam.ParameterName),
			Value:        aws.ToString(currentParam.ParameterValue),
			DefaultValue: "",
			IsModifiable: aws.ToBool(currentParam.IsModifiable),
			ApplyType:    aws.ToString(currentParam.ApplyType),
			DataType:     aws.ToString(currentParam.DataType),
		}

		// Categorize parameters
		if c.isReplicationParameter(paramName) {
			configParam.IsReplication = true
		}
		if c.isBackupParameter(paramName) {
			configParam.IsBackup = true
		}

		configParams = append(configParams, configParam)

		// Check for changes only if we have previous data
		if exists {
			if lastParam, existed := lastParams[paramName]; existed {
				oldValue := aws.ToString(lastParam.ParameterValue)
				newValue := aws.ToString(currentParam.ParameterValue)

				if oldValue != newValue {
					parameterChanges = append(parameterChanges, sentinelTypes.ParameterChange{
						Name:        paramName,
						OldValue:    oldValue,
						NewValue:    newValue,
						Description: aws.ToString(currentParam.Description),
					})
				}
			}
		}
	}

	// Generate initial configuration event if this is the first time
	if !exists {
		c.logger.WithField("instance", instanceID).Info("Generating initial RDS configuration event")
		return []sentinelTypes.Event{c.createInitialConfigEvent(instanceID, parameterGroupName, configParams)}
	}

	// Generate change event only if there are changes
	if len(parameterChanges) == 0 {
		return nil
	}

	return []sentinelTypes.Event{c.createConfigEvent(instanceID, parameterGroupName, configParams, parameterChanges)}
}

// createConfigEvent creates an RDS configuration event
func (c *ConfigCollector) createConfigEvent(instanceID, parameterGroupName string, parameters []sentinelTypes.ConfigParameter, changes []sentinelTypes.ParameterChange) sentinelTypes.Event {
	now := time.Now()

	rdsEvent := sentinelTypes.RDSConfigEvent{
		InstanceID:       instanceID,
		ParameterGroup:   parameterGroupName,
		Parameters:       parameters,
		ParameterChanges: changes,
		LastModified:     now.Unix(),
		ApplyMethod:      "pending-reboot", // Most parameter changes require restart
	}

	event := sentinelTypes.Event{
		ID:        c.generateEventID(instanceID, now),
		Timestamp: now,
		Type:      sentinelTypes.EventTypeRDSConfig,
		Source:    "rds_config_collector",
		RDSConfig: &rdsEvent,
	}

	return event
}

// createInitialConfigEvent creates an initial RDS configuration event (baseline)
func (c *ConfigCollector) createInitialConfigEvent(instanceID, parameterGroupName string, parameters []sentinelTypes.ConfigParameter) sentinelTypes.Event {
	now := time.Now()

	rdsEvent := sentinelTypes.RDSConfigEvent{
		InstanceID:       instanceID,
		ParameterGroup:   parameterGroupName,
		Parameters:       parameters,
		ParameterChanges: []sentinelTypes.ParameterChange{}, // No changes for initial config
		LastModified:     now.Unix(),
		ApplyMethod:      "initial-baseline", // Indicates this is the initial configuration
	}

	event := sentinelTypes.Event{
		ID:        c.generateEventID(instanceID, now),
		Timestamp: now,
		Type:      sentinelTypes.EventTypeRDSConfig,
		Source:    "rds_config_collector",
		RDSConfig: &rdsEvent,
	}

	return event
}

// isReplicationParameter checks if a parameter is related to replication
func (c *ConfigCollector) isReplicationParameter(paramName string) bool {
	replicationParams := []string{
		"wal_level",
		"max_wal_senders",
		"max_replication_slots",
		"hot_standby",
		"hot_standby_feedback",
		"wal_receiver_status_interval",
		"max_standby_streaming_delay",
		"max_standby_archive_delay",
	}

	for _, param := range replicationParams {
		if param == paramName {
			return true
		}
	}
	return false
}

// isBackupParameter checks if a parameter is related to backup
func (c *ConfigCollector) isBackupParameter(paramName string) bool {
	backupParams := []string{
		"archive_mode",
		"archive_command",
		"archive_timeout",
		"wal_keep_segments",
		"checkpoint_segments",
		"checkpoint_completion_target",
	}

	for _, param := range backupParams {
		if param == paramName {
			return true
		}
	}
	return false
}

// containsInstance checks if an instance ID is in the configured instances list
func (c *ConfigCollector) containsInstance(instanceID string) bool {
	for _, configuredInstance := range c.config.Instances {
		if configuredInstance == instanceID {
			return true
		}
	}
	return false
}

// generateEventID generates a unique event ID
func (c *ConfigCollector) generateEventID(instanceID string, timestamp time.Time) string {
	return fmt.Sprintf("rds-config-%s-%d", instanceID, timestamp.UnixNano())
}

// isRunning returns whether the collector is currently running
func (c *ConfigCollector) isRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}
