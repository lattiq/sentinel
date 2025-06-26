package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	awsClient "github.com/lattiq/sentinel/internal/aws"
	"github.com/lattiq/sentinel/internal/config"
	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

// ComponentHealthChecker interface for different health checkers
type ComponentHealthChecker interface {
	Name() string
	Check(ctx context.Context) *sentinelTypes.HealthEvent
}

// Collector implements general health monitoring for external systems
type Collector struct {
	config     *config.Config
	awsManager *awsClient.ClientManager
	logger     *logrus.Entry
	checkers   []ComponentHealthChecker

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

	// Health tracking for change detection
	lastHealthStates map[string]string // componentName -> status
}

// NewCollector creates a new health collector
func NewCollector(cfg *config.Config, awsManager *awsClient.ClientManager) (*Collector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component":       "health_collector",
		"report_interval": cfg.Health.ReportInterval,
	})

	collector := &Collector{
		config:           cfg,
		awsManager:       awsManager,
		logger:           logger,
		eventsChan:       make(chan sentinelTypes.Event, 1000),
		subscribers:      make([]chan sentinelTypes.Event, 0),
		lastHealthStates: make(map[string]string),
		health: sentinelTypes.CollectorHealth{
			Status:      string(sentinelTypes.HealthStatusStopped),
			Performance: sentinelTypes.PerformanceStats{},
		},
	}

	// Initialize health checkers
	collector.initializeHealthCheckers()

	logger.Info("Health collector created")
	return collector, nil
}

// Name returns the collector name
func (c *Collector) Name() string {
	return "health"
}

// Start begins the health monitoring process
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector is already running")
	}

	c.logger.Info("Starting health collector")
	c.running = true
	c.startTime = time.Now()
	c.health.Status = string(sentinelTypes.HealthStatusHealthy)
	c.health.LastCollection = time.Now()

	// Start collection goroutine
	go c.collectLoop(ctx)

	// Start event distribution goroutine
	go c.distributeEvents(ctx)

	c.logger.Info("Health collector started successfully")
	return nil
}

// Stop gracefully stops the collector
func (c *Collector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.logger.Info("Stopping health collector")
	c.running = false
	c.health.Status = string(sentinelTypes.HealthStatusStopped)

	// Close events channel
	close(c.eventsChan)

	c.logger.Info("Health collector stopped")
	return nil
}

// Collect performs a single collection cycle (for manual triggering)
func (c *Collector) Collect(ctx context.Context) ([]sentinelTypes.Event, error) {
	if !c.config.Health.Enabled {
		return nil, nil
	}

	startTime := time.Now()
	events, err := c.fetchHealthEvents(ctx)
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
func (c *Collector) Health() sentinelTypes.CollectorHealth {
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
func (c *Collector) Subscribe() <-chan sentinelTypes.Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	eventChan := make(chan sentinelTypes.Event, 100)
	c.subscribers = append(c.subscribers, eventChan)
	return eventChan
}

// collectLoop runs the periodic collection process
func (c *Collector) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.Health.ReportInterval)
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
		c.logger.WithError(err).Error("Initial health collection failed")
	}

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Health collection loop stopping")
			return
		case <-ticker.C:
			if !c.isRunning() {
				return
			}

			events, err := c.Collect(ctx)
			if err != nil {
				c.logger.WithError(err).Error("Failed to collect health events")
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
func (c *Collector) distributeEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Health event distribution stopping")
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

// fetchHealthEvents retrieves and processes health events
func (c *Collector) fetchHealthEvents(ctx context.Context) ([]sentinelTypes.Event, error) {
	var events []sentinelTypes.Event

	// Check health of all registered components
	for _, checker := range c.checkers {
		healthEvent := checker.Check(ctx)
		if healthEvent != nil {
			// Check if status changed
			if c.hasStatusChanged(healthEvent.ComponentName, healthEvent.Status) {
				event := c.createHealthEvent(healthEvent)
				events = append(events, event)
			}
		}
	}

	return events, nil
}

// hasStatusChanged checks if component health status has changed
func (c *Collector) hasStatusChanged(componentName, currentStatus string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	lastStatus, exists := c.lastHealthStates[componentName]
	c.lastHealthStates[componentName] = currentStatus

	// Always report if it's the first check or status changed
	return !exists || lastStatus != currentStatus
}

// createHealthEvent creates a health event
func (c *Collector) createHealthEvent(healthEvent *sentinelTypes.HealthEvent) sentinelTypes.Event {
	now := time.Now()

	event := sentinelTypes.Event{
		ID:        c.generateEventID(healthEvent.ComponentName, now),
		Timestamp: now,
		Type:      sentinelTypes.EventTypeHealth,
		Source:    "health_collector",
		Health:    healthEvent,
	}

	return event
}

// initializeHealthCheckers initializes health checkers for enabled components
func (c *Collector) initializeHealthCheckers() {
	// RDS Health Checker (if RDS is enabled)
	if c.config.DataSources.RDS.Enabled {
		rdsChecker := NewRDSHealthChecker(c.config, c.awsManager)
		c.checkers = append(c.checkers, rdsChecker)
		c.logger.Info("RDS health checker initialized")
	}

	// CloudWatch Health Checker (if query logs are enabled)
	if c.config.DataSources.QueryLogs.Enabled {
		cloudWatchChecker := NewCloudWatchHealthChecker(c.config, c.awsManager)
		c.checkers = append(c.checkers, cloudWatchChecker)
		c.logger.Info("CloudWatch health checker initialized")
	}

	// S3 Health Checker (if CloudTrail is enabled)
	if c.config.DataSources.CloudTrail.Enabled {
		s3Checker := NewS3HealthChecker(c.config, c.awsManager)
		c.checkers = append(c.checkers, s3Checker)
		c.logger.Info("S3 health checker initialized")
	}

	// Hub Health Checker
	hubChecker := NewHubHealthChecker(c.config)
	c.checkers = append(c.checkers, hubChecker)
	c.logger.Info("Hub health checker initialized")

	c.logger.WithField("checker_count", len(c.checkers)).Info("All health checkers initialized")
}

// generateEventID generates a unique event ID
func (c *Collector) generateEventID(componentName string, timestamp time.Time) string {
	return fmt.Sprintf("health-%s-%d", componentName, timestamp.UnixNano())
}

// isRunning returns whether the collector is currently running
func (c *Collector) isRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}
