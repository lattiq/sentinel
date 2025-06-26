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

// SnapshotsCollector implements RDS snapshots collection
type SnapshotsCollector struct {
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

	// Snapshot tracking for change detection
	lastSnapshots map[string]types.DBSnapshot
}

// NewSnapshotsCollector creates a new RDS snapshots collector
func NewSnapshotsCollector(cfg *config.RDSConfig, awsManager *awsClient.ClientManager) (*SnapshotsCollector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if awsManager == nil {
		return nil, fmt.Errorf("AWS manager is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component":             "rds_snapshots_collector",
		"monitor_all_instances": cfg.MonitorAllInstances,
		"poll_interval":         cfg.PollIntervals.Snapshots,
	})

	collector := &SnapshotsCollector{
		config:        cfg,
		awsManager:    awsManager,
		logger:        logger,
		eventsChan:    make(chan sentinelTypes.Event, 1000),
		subscribers:   make([]chan sentinelTypes.Event, 0),
		lastSnapshots: make(map[string]types.DBSnapshot),
		health: sentinelTypes.CollectorHealth{
			Status:      string(sentinelTypes.HealthStatusStopped),
			Performance: sentinelTypes.PerformanceStats{},
		},
	}

	logger.Info("RDS snapshots collector created")
	return collector, nil
}

// Name returns the collector name
func (c *SnapshotsCollector) Name() string {
	return "rds_snapshots"
}

// Start begins the RDS snapshots collection process
func (c *SnapshotsCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector is already running")
	}

	c.logger.Info("Starting RDS snapshots collector")
	c.running = true
	c.startTime = time.Now()
	c.health.Status = string(sentinelTypes.HealthStatusHealthy)
	c.health.LastCollection = time.Now()

	// Start collection goroutine
	go c.collectLoop(ctx)

	// Start event distribution goroutine
	go c.distributeEvents(ctx)

	c.logger.Info("RDS snapshots collector started successfully")
	return nil
}

// Stop gracefully stops the collector
func (c *SnapshotsCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.logger.Info("Stopping RDS snapshots collector")
	c.running = false
	c.health.Status = string(sentinelTypes.HealthStatusStopped)

	// Close events channel
	close(c.eventsChan)

	c.logger.Info("RDS snapshots collector stopped")
	return nil
}

// Collect performs a single collection cycle (for manual triggering)
func (c *SnapshotsCollector) Collect(ctx context.Context) ([]sentinelTypes.Event, error) {
	if !c.config.Enabled {
		return nil, nil
	}

	startTime := time.Now()
	events, err := c.fetchSnapshotEvents(ctx)
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
func (c *SnapshotsCollector) Health() sentinelTypes.CollectorHealth {
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
func (c *SnapshotsCollector) Subscribe() <-chan sentinelTypes.Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	eventChan := make(chan sentinelTypes.Event, 100)
	c.subscribers = append(c.subscribers, eventChan)
	return eventChan
}

// collectLoop runs the periodic collection process
func (c *SnapshotsCollector) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.PollIntervals.Snapshots)
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
		c.logger.WithError(err).Error("Initial RDS snapshots collection failed")
	}

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("RDS snapshots collection loop stopping")
			return
		case <-ticker.C:
			if !c.isRunning() {
				return
			}

			events, err := c.Collect(ctx)
			if err != nil {
				c.logger.WithError(err).Error("Failed to collect RDS snapshots")
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
func (c *SnapshotsCollector) distributeEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("RDS snapshots event distribution stopping")
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

// fetchSnapshotEvents retrieves and processes RDS snapshot events
func (c *SnapshotsCollector) fetchSnapshotEvents(ctx context.Context) ([]sentinelTypes.Event, error) {
	rdsClient, err := c.awsManager.GetRDSClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS client: %w", err)
	}

	var events []sentinelTypes.Event
	var marker *string

	for {
		input := &rds.DescribeDBSnapshotsInput{Marker: marker}

		result, err := rdsClient.DescribeDBSnapshots(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB snapshots: %w", err)
		}

		// Process snapshots and detect changes
		for _, snapshot := range result.DBSnapshots {
			// Filter by configured instances if needed
			if !c.config.MonitorAllInstances && len(c.config.Instances) > 0 {
				instanceID := aws.ToString(snapshot.DBInstanceIdentifier)
				if !c.containsInstance(instanceID) {
					continue
				}
			}

			// Check for changes and generate events
			if event := c.processSnapshot(snapshot); event != nil {
				events = append(events, *event)
			}
		}

		// Check if there are more results
		if result.Marker == nil || *result.Marker == "" {
			break
		}
		marker = result.Marker
	}

	return events, nil
}

// processSnapshot processes a single RDS snapshot and generates events for changes
func (c *SnapshotsCollector) processSnapshot(snapshot types.DBSnapshot) *sentinelTypes.Event {
	snapshotID := aws.ToString(snapshot.DBSnapshotIdentifier)

	// Check if this is a new snapshot or has changes
	c.mu.Lock()
	lastSnapshot, exists := c.lastSnapshots[snapshotID]
	c.lastSnapshots[snapshotID] = snapshot
	c.mu.Unlock()

	// If this is the first time seeing this snapshot, generate event for new snapshot
	if !exists {
		return c.createSnapshotEvent(snapshot, true)
	}

	// Check for status changes
	if aws.ToString(lastSnapshot.Status) != aws.ToString(snapshot.Status) {
		return c.createSnapshotEvent(snapshot, false)
	}

	return nil
}

// createSnapshotEvent creates an RDS snapshot event
func (c *SnapshotsCollector) createSnapshotEvent(snapshot types.DBSnapshot, isNew bool) *sentinelTypes.Event {
	now := time.Now()

	rdsEvent := sentinelTypes.RDSSnapshotEvent{
		SnapshotID:       aws.ToString(snapshot.DBSnapshotIdentifier),
		InstanceID:       aws.ToString(snapshot.DBInstanceIdentifier),
		SnapshotType:     aws.ToString(snapshot.SnapshotType),
		Status:           aws.ToString(snapshot.Status),
		AllocatedStorage: int(aws.ToInt32(snapshot.AllocatedStorage)),
		Encrypted:        aws.ToBool(snapshot.Encrypted),
		Engine:           aws.ToString(snapshot.Engine),
		EngineVersion:    aws.ToString(snapshot.EngineVersion),
		LicenseModel:     aws.ToString(snapshot.LicenseModel),
		Port:             int(aws.ToInt32(snapshot.Port)),
	}

	// Add timestamps
	if snapshot.SnapshotCreateTime != nil {
		rdsEvent.CreateTime = snapshot.SnapshotCreateTime.Unix()
	}
	if snapshot.InstanceCreateTime != nil {
		rdsEvent.DatabaseTime = snapshot.InstanceCreateTime.Unix()
	}

	// Add KMS key if available
	if snapshot.KmsKeyId != nil {
		rdsEvent.KmsKeyId = aws.ToString(snapshot.KmsKeyId)
	}

	event := sentinelTypes.Event{
		ID:          c.generateEventID(aws.ToString(snapshot.DBSnapshotIdentifier), now),
		Timestamp:   now,
		Type:        sentinelTypes.EventTypeRDSSnapshot,
		Source:      "rds_snapshots_collector",
		RDSSnapshot: &rdsEvent,
	}

	return &event
}

// containsInstance checks if an instance ID is in the configured instances list
func (c *SnapshotsCollector) containsInstance(instanceID string) bool {
	for _, configuredInstance := range c.config.Instances {
		if configuredInstance == instanceID {
			return true
		}
	}
	return false
}

// generateEventID generates a unique event ID
func (c *SnapshotsCollector) generateEventID(snapshotID string, timestamp time.Time) string {
	return fmt.Sprintf("rds-snapshot-%s-%d", snapshotID, timestamp.UnixNano())
}

// isRunning returns whether the collector is currently running
func (c *SnapshotsCollector) isRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}
