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

// ClustersCollector implements Aurora clusters collection
type ClustersCollector struct {
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

	// Cluster tracking for change detection
	lastClusters map[string]types.DBCluster
}

// NewClustersCollector creates a new Aurora clusters collector
func NewClustersCollector(cfg *config.RDSConfig, awsManager *awsClient.ClientManager) (*ClustersCollector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if awsManager == nil {
		return nil, fmt.Errorf("AWS manager is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component":            "rds_clusters_collector",
		"monitor_all_clusters": cfg.MonitorAllClusters,
		"poll_interval":        cfg.PollIntervals.Clusters,
	})

	collector := &ClustersCollector{
		config:       cfg,
		awsManager:   awsManager,
		logger:       logger,
		eventsChan:   make(chan sentinelTypes.Event, 1000),
		subscribers:  make([]chan sentinelTypes.Event, 0),
		lastClusters: make(map[string]types.DBCluster),
		health: sentinelTypes.CollectorHealth{
			Status:      string(sentinelTypes.HealthStatusStopped),
			Performance: sentinelTypes.PerformanceStats{},
		},
	}

	logger.Info("Aurora clusters collector created")
	return collector, nil
}

// Name returns the collector name
func (c *ClustersCollector) Name() string {
	return "rds_clusters"
}

// Start begins the Aurora clusters collection process
func (c *ClustersCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector is already running")
	}

	c.logger.Info("Starting Aurora clusters collector")
	c.running = true
	c.startTime = time.Now()
	c.health.Status = string(sentinelTypes.HealthStatusHealthy)
	c.health.LastCollection = time.Now()

	// Start collection goroutine
	go c.collectLoop(ctx)

	// Start event distribution goroutine
	go c.distributeEvents(ctx)

	c.logger.Info("Aurora clusters collector started successfully")
	return nil
}

// Stop gracefully stops the collector
func (c *ClustersCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.logger.Info("Stopping Aurora clusters collector")
	c.running = false
	c.health.Status = string(sentinelTypes.HealthStatusStopped)

	// Close events channel
	close(c.eventsChan)

	c.logger.Info("Aurora clusters collector stopped")
	return nil
}

// Collect performs a single collection cycle (for manual triggering)
func (c *ClustersCollector) Collect(ctx context.Context) ([]sentinelTypes.Event, error) {
	if !c.config.Enabled {
		return nil, nil
	}

	startTime := time.Now()
	events, err := c.fetchClusterEvents(ctx)
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
func (c *ClustersCollector) Health() sentinelTypes.CollectorHealth {
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
func (c *ClustersCollector) Subscribe() <-chan sentinelTypes.Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	eventChan := make(chan sentinelTypes.Event, 100)
	c.subscribers = append(c.subscribers, eventChan)
	return eventChan
}

// collectLoop runs the periodic collection process
func (c *ClustersCollector) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.PollIntervals.Clusters)
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
		c.logger.WithError(err).Error("Initial Aurora clusters collection failed")
	}

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Aurora clusters collection loop stopping")
			return
		case <-ticker.C:
			if !c.isRunning() {
				return
			}

			events, err := c.Collect(ctx)
			if err != nil {
				c.logger.WithError(err).Error("Failed to collect Aurora clusters")
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
func (c *ClustersCollector) distributeEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Aurora clusters event distribution stopping")
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

// fetchClusterEvents retrieves and processes Aurora cluster events
func (c *ClustersCollector) fetchClusterEvents(ctx context.Context) ([]sentinelTypes.Event, error) {
	rdsClient, err := c.awsManager.GetRDSClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS client: %w", err)
	}

	var events []sentinelTypes.Event
	var marker *string

	for {
		input := &rds.DescribeDBClustersInput{Marker: marker}

		result, err := rdsClient.DescribeDBClusters(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
		}

		// Process clusters and detect changes
		for _, cluster := range result.DBClusters {
			// Filter by configured clusters if needed
			if !c.config.MonitorAllClusters && len(c.config.Clusters) > 0 {
				clusterID := aws.ToString(cluster.DBClusterIdentifier)
				if !c.containsCluster(clusterID) {
					continue
				}
			}

			// Check for changes and generate events
			if event := c.processCluster(cluster); event != nil {
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

// processCluster processes a single Aurora cluster and generates events for changes
func (c *ClustersCollector) processCluster(cluster types.DBCluster) *sentinelTypes.Event {
	clusterID := aws.ToString(cluster.DBClusterIdentifier)

	// Check if this is a new cluster or has changes
	c.mu.Lock()
	lastCluster, exists := c.lastClusters[clusterID]
	c.lastClusters[clusterID] = cluster
	c.mu.Unlock()

	// If this is the first time seeing this cluster, generate initial state event
	if !exists {
		c.logger.WithField("cluster_id", clusterID).Debug("Discovered Aurora cluster - generating initial state event")
		return c.createClusterEvent(cluster)
	}

	// Check for significant changes that indicate potential abuse
	hasChanges := false

	// Check for cluster member changes
	if c.hasClusterMemberChanges(lastCluster, cluster) {
		hasChanges = true
	}

	// Check for status changes
	if aws.ToString(lastCluster.Status) != aws.ToString(cluster.Status) {
		hasChanges = true
	}

	// Check for backup retention changes
	if aws.ToInt32(lastCluster.BackupRetentionPeriod) != aws.ToInt32(cluster.BackupRetentionPeriod) {
		hasChanges = true
	}

	// Check for engine version changes
	if aws.ToString(lastCluster.EngineVersion) != aws.ToString(cluster.EngineVersion) {
		hasChanges = true
	}

	// Only generate event if there are significant changes
	if !hasChanges {
		return nil
	}

	return c.createClusterEvent(cluster)
}

// hasClusterMemberChanges checks if cluster member configuration has changed
func (c *ClustersCollector) hasClusterMemberChanges(last, current types.DBCluster) bool {
	lastMembers := last.DBClusterMembers
	currentMembers := current.DBClusterMembers

	if len(lastMembers) != len(currentMembers) {
		return true
	}

	// Check if member lists are different
	memberMap := make(map[string]bool)
	for _, member := range lastMembers {
		memberMap[aws.ToString(member.DBInstanceIdentifier)] = true
	}

	for _, member := range currentMembers {
		if !memberMap[aws.ToString(member.DBInstanceIdentifier)] {
			return true
		}
	}

	return false
}

// createClusterEvent creates an Aurora cluster event
func (c *ClustersCollector) createClusterEvent(cluster types.DBCluster) *sentinelTypes.Event {
	now := time.Now()

	// Extract cluster member identifiers
	var clusterMembers []string
	for _, member := range cluster.DBClusterMembers {
		clusterMembers = append(clusterMembers, aws.ToString(member.DBInstanceIdentifier))
	}

	// Extract availability zones
	var availabilityZones []string
	for _, az := range cluster.AvailabilityZones {
		availabilityZones = append(availabilityZones, az)
	}

	rdsEvent := sentinelTypes.RDSClusterEvent{
		ClusterID:               aws.ToString(cluster.DBClusterIdentifier),
		ClusterArn:              aws.ToString(cluster.DBClusterArn),
		Engine:                  aws.ToString(cluster.Engine),
		EngineVersion:           aws.ToString(cluster.EngineVersion),
		EngineMode:              aws.ToString(cluster.EngineMode),
		Status:                  aws.ToString(cluster.Status),
		LastModified:            cluster.ClusterCreateTime.Unix(),
		DatabaseName:            aws.ToString(cluster.DatabaseName),
		MasterUsername:          aws.ToString(cluster.MasterUsername),
		Port:                    int(aws.ToInt32(cluster.Port)),
		AllocatedStorage:        int(aws.ToInt32(cluster.AllocatedStorage)),
		StorageEncrypted:        aws.ToBool(cluster.StorageEncrypted),
		KmsKeyId:                aws.ToString(cluster.KmsKeyId),
		MultiAZ:                 aws.ToBool(cluster.MultiAZ),
		AvailabilityZones:       availabilityZones,
		ClusterMembers:          clusterMembers,
		BackupRetentionPeriod:   int(aws.ToInt32(cluster.BackupRetentionPeriod)),
		DeletionProtection:      aws.ToBool(cluster.DeletionProtection),
		AutoMinorVersionUpgrade: aws.ToBool(cluster.AutoMinorVersionUpgrade),
	}

	// Add endpoint information if available
	if cluster.ReaderEndpoint != nil {
		rdsEvent.ReaderEndpoint = aws.ToString(cluster.ReaderEndpoint)
	}
	if cluster.Endpoint != nil {
		rdsEvent.Endpoint = aws.ToString(cluster.Endpoint)
	}

	// Add backup window information
	if cluster.PreferredBackupWindow != nil {
		rdsEvent.PreferredBackupWindow = aws.ToString(cluster.PreferredBackupWindow)
	}
	if cluster.PreferredMaintenanceWindow != nil {
		rdsEvent.PreferredMaintenanceWindow = aws.ToString(cluster.PreferredMaintenanceWindow)
	}

	// Add VPC information if available
	if cluster.DBSubnetGroup != nil {
		rdsEvent.SubnetGroup = aws.ToString(cluster.DBSubnetGroup)
	}

	// Add activity stream information if available
	if len(cluster.ActivityStreamStatus) > 0 {
		rdsEvent.ActivityStreamStatus = string(cluster.ActivityStreamStatus)
	}
	if len(cluster.ActivityStreamMode) > 0 {
		rdsEvent.ActivityStreamMode = string(cluster.ActivityStreamMode)
	}

	// Add backtrack window for Aurora MySQL
	if cluster.BacktrackWindow != nil {
		rdsEvent.BacktrackWindow = int(aws.ToInt64(cluster.BacktrackWindow))
	}

	// Add clone group information if available
	if cluster.CloneGroupId != nil {
		rdsEvent.CloneGroupId = aws.ToString(cluster.CloneGroupId)
	}

	event := sentinelTypes.Event{
		ID:         c.generateEventID(aws.ToString(cluster.DBClusterIdentifier), now),
		Timestamp:  now,
		Type:       sentinelTypes.EventTypeRDSCluster,
		Source:     "rds_clusters_collector",
		RDSCluster: &rdsEvent,
	}

	return &event
}

// containsCluster checks if a cluster ID is in the configured clusters list
func (c *ClustersCollector) containsCluster(clusterID string) bool {
	for _, configuredCluster := range c.config.Clusters {
		if configuredCluster == clusterID {
			return true
		}
	}
	return false
}

// generateEventID generates a unique event ID
func (c *ClustersCollector) generateEventID(clusterID string, timestamp time.Time) string {
	return fmt.Sprintf("rds-cluster-%s-%d", clusterID, timestamp.UnixNano())
}

// isRunning returns whether the collector is currently running
func (c *ClustersCollector) isRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}
