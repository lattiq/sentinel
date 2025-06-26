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

// InstancesCollector implements RDS instances collection
type InstancesCollector struct {
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

	// Instance tracking for change detection
	lastInstances map[string]types.DBInstance
}

// NewInstancesCollector creates a new RDS instances collector
func NewInstancesCollector(cfg *config.RDSConfig, awsManager *awsClient.ClientManager) (*InstancesCollector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if awsManager == nil {
		return nil, fmt.Errorf("AWS manager is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component":             "rds_instances_collector",
		"monitor_all_instances": cfg.MonitorAllInstances,
		"poll_interval":         cfg.PollIntervals.Instances,
	})

	collector := &InstancesCollector{
		config:        cfg,
		awsManager:    awsManager,
		logger:        logger,
		eventsChan:    make(chan sentinelTypes.Event, 1000),
		subscribers:   make([]chan sentinelTypes.Event, 0),
		lastInstances: make(map[string]types.DBInstance),
		health: sentinelTypes.CollectorHealth{
			Status:      string(sentinelTypes.HealthStatusStopped),
			Performance: sentinelTypes.PerformanceStats{},
		},
	}

	logger.Info("RDS instances collector created")
	return collector, nil
}

// Name returns the collector name
func (c *InstancesCollector) Name() string {
	return "rds_instances"
}

// Start begins the RDS instances collection process
func (c *InstancesCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector is already running")
	}

	c.logger.Info("Starting RDS instances collector")
	c.running = true
	c.startTime = time.Now()
	c.health.Status = string(sentinelTypes.HealthStatusHealthy)
	c.health.LastCollection = time.Now()

	// Start collection goroutine
	go c.collectLoop(ctx)

	// Start event distribution goroutine
	go c.distributeEvents(ctx)

	c.logger.Info("RDS instances collector started successfully")
	return nil
}

// Stop gracefully stops the collector
func (c *InstancesCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.logger.Info("Stopping RDS instances collector")
	c.running = false
	c.health.Status = string(sentinelTypes.HealthStatusStopped)

	// Close events channel
	close(c.eventsChan)

	c.logger.Info("RDS instances collector stopped")
	return nil
}

// Collect performs a single collection cycle (for manual triggering)
func (c *InstancesCollector) Collect(ctx context.Context) ([]sentinelTypes.Event, error) {
	if !c.config.Enabled {
		return nil, nil
	}

	startTime := time.Now()
	events, err := c.fetchInstanceEvents(ctx)
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
func (c *InstancesCollector) Health() sentinelTypes.CollectorHealth {
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
func (c *InstancesCollector) Subscribe() <-chan sentinelTypes.Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	eventChan := make(chan sentinelTypes.Event, 100)
	c.subscribers = append(c.subscribers, eventChan)
	return eventChan
}

// collectLoop runs the periodic collection process
func (c *InstancesCollector) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.PollIntervals.Instances)
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
		c.logger.WithError(err).Error("Initial RDS instances collection failed")
	}

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("RDS instances collection loop stopping")
			return
		case <-ticker.C:
			if !c.isRunning() {
				return
			}

			events, err := c.Collect(ctx)
			if err != nil {
				c.logger.WithError(err).Error("Failed to collect RDS instances")
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
func (c *InstancesCollector) distributeEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("RDS instances event distribution stopping")
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

// fetchInstanceEvents retrieves and processes RDS instance events
func (c *InstancesCollector) fetchInstanceEvents(ctx context.Context) ([]sentinelTypes.Event, error) {
	rdsClient, err := c.awsManager.GetRDSClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS client: %w", err)
	}

	var events []sentinelTypes.Event
	var marker *string

	for {
		input := &rds.DescribeDBInstancesInput{Marker: marker}

		result, err := rdsClient.DescribeDBInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB instances: %w", err)
		}

		// Process instances and detect changes
		for _, instance := range result.DBInstances {
			// Filter by configured instances if needed
			if !c.config.MonitorAllInstances && len(c.config.Instances) > 0 {
				instanceID := aws.ToString(instance.DBInstanceIdentifier)
				if !c.containsInstance(instanceID) {
					continue
				}
			}

			// Check for changes and generate events
			if event := c.processInstance(instance); event != nil {
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

// processInstance processes a single RDS instance and generates events for changes
func (c *InstancesCollector) processInstance(instance types.DBInstance) *sentinelTypes.Event {
	instanceID := aws.ToString(instance.DBInstanceIdentifier)

	// Check if this is a new instance or has changes
	c.mu.Lock()
	lastInstance, exists := c.lastInstances[instanceID]
	c.lastInstances[instanceID] = instance
	c.mu.Unlock()

	// If this is the first time seeing this instance, generate initial state event
	if !exists {
		c.logger.WithField("instance_id", instanceID).Debug("Discovered RDS instance - generating initial state event")
		return c.createInstanceEvent(instance)
	}

	// Check for significant changes that indicate potential abuse
	hasChanges := false

	// Check for read replica changes
	if c.hasReplicaChanges(lastInstance, instance) {
		hasChanges = true
	}

	// Check for status changes
	if aws.ToString(lastInstance.DBInstanceStatus) != aws.ToString(instance.DBInstanceStatus) {
		hasChanges = true
	}

	// Check for backup retention changes
	if aws.ToInt32(lastInstance.BackupRetentionPeriod) != aws.ToInt32(instance.BackupRetentionPeriod) {
		hasChanges = true
	}

	// Only generate event if there are significant changes
	if !hasChanges {
		return nil
	}

	return c.createInstanceEvent(instance)
}

// hasReplicaChanges checks if read replica configuration has changed
func (c *InstancesCollector) hasReplicaChanges(last, current types.DBInstance) bool {
	lastReplicas := last.ReadReplicaDBInstanceIdentifiers
	currentReplicas := current.ReadReplicaDBInstanceIdentifiers

	if len(lastReplicas) != len(currentReplicas) {
		return true
	}

	// Check if replica lists are different
	replicaMap := make(map[string]bool)
	for _, replica := range lastReplicas {
		replicaMap[replica] = true
	}

	for _, replica := range currentReplicas {
		if !replicaMap[replica] {
			return true
		}
	}

	return false
}

// createInstanceEvent creates an RDS instance event
func (c *InstancesCollector) createInstanceEvent(instance types.DBInstance) *sentinelTypes.Event {
	now := time.Now()

	rdsEvent := sentinelTypes.RDSInstanceEvent{
		InstanceID:            aws.ToString(instance.DBInstanceIdentifier),
		Status:                aws.ToString(instance.DBInstanceStatus),
		Engine:                aws.ToString(instance.Engine),
		EngineVersion:         aws.ToString(instance.EngineVersion),
		InstanceClass:         aws.ToString(instance.DBInstanceClass),
		LastModified:          instance.InstanceCreateTime.Unix(),
		ReadReplicas:          instance.ReadReplicaDBInstanceIdentifiers,
		BackupRetentionPeriod: int(aws.ToInt32(instance.BackupRetentionPeriod)),
		MultiAZ:               aws.ToBool(instance.MultiAZ),
		AllocatedStorage:      int(aws.ToInt32(instance.AllocatedStorage)),
		StorageType:           aws.ToString(instance.StorageType),
		StorageEncrypted:      aws.ToBool(instance.StorageEncrypted),
		PubliclyAccessible:    aws.ToBool(instance.PubliclyAccessible),
	}

	// Add source replica information if this is a replica
	if instance.ReadReplicaSourceDBInstanceIdentifier != nil {
		readReplicaSource := aws.ToString(instance.ReadReplicaSourceDBInstanceIdentifier)
		rdsEvent.ReadReplicaSource = &readReplicaSource
	}

	// Add VPC information if available
	if instance.DBSubnetGroup != nil && instance.DBSubnetGroup.VpcId != nil {
		rdsEvent.VpcId = aws.ToString(instance.DBSubnetGroup.VpcId)
		rdsEvent.SubnetGroup = aws.ToString(instance.DBSubnetGroup.DBSubnetGroupName)
	}

	// Add availability zone if available
	if instance.AvailabilityZone != nil {
		rdsEvent.AvailabilityZone = aws.ToString(instance.AvailabilityZone)
	}

	// Add backup window information
	if instance.PreferredBackupWindow != nil {
		rdsEvent.PreferredBackupWindow = aws.ToString(instance.PreferredBackupWindow)
	}
	if instance.PreferredMaintenanceWindow != nil {
		rdsEvent.PreferredMaintenanceWindow = aws.ToString(instance.PreferredMaintenanceWindow)
	}

	event := sentinelTypes.Event{
		ID:          c.generateEventID(aws.ToString(instance.DBInstanceIdentifier), now),
		Timestamp:   now,
		Type:        sentinelTypes.EventTypeRDSInstance,
		Source:      "rds_instances_collector",
		RDSInstance: &rdsEvent,
	}

	return &event
}

// containsInstance checks if an instance ID is in the configured instances list
func (c *InstancesCollector) containsInstance(instanceID string) bool {
	for _, configuredInstance := range c.config.Instances {
		if configuredInstance == instanceID {
			return true
		}
	}
	return false
}

// generateEventID generates a unique event ID
func (c *InstancesCollector) generateEventID(instanceID string, timestamp time.Time) string {
	return fmt.Sprintf("rds-instance-%s-%d", instanceID, timestamp.UnixNano())
}

// isRunning returns whether the collector is currently running
func (c *InstancesCollector) isRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}
