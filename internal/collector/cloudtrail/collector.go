package cloudtrail

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"

	awsClient "github.com/lattiq/sentinel/internal/aws"
	"github.com/lattiq/sentinel/internal/config"
	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

// CloudTrailLogRecord represents the structure of a CloudTrail log file
type CloudTrailLogRecord struct {
	Records []CloudTrailRecord `json:"Records"`
}

// CloudTrailRecord represents a single CloudTrail event record
type CloudTrailRecord struct {
	EventVersion        string                 `json:"eventVersion"`
	UserIdentity        CloudTrailUserIdentity `json:"userIdentity"`
	EventTime           time.Time              `json:"eventTime"`
	EventSource         string                 `json:"eventSource"`
	EventName           string                 `json:"eventName"`
	AWSRegion           string                 `json:"awsRegion"`
	SourceIPAddress     string                 `json:"sourceIPAddress"`
	UserAgent           string                 `json:"userAgent"`
	RequestParameters   map[string]interface{} `json:"requestParameters"`
	ResponseElements    map[string]interface{} `json:"responseElements"`
	RequestID           string                 `json:"requestID"`
	EventID             string                 `json:"eventID"`
	ReadOnly            bool                   `json:"readOnly"`
	Resources           []CloudTrailResource   `json:"resources,omitempty"`
	EventType           string                 `json:"eventType"`
	ErrorCode           string                 `json:"errorCode,omitempty"`
	ErrorMessage        string                 `json:"errorMessage,omitempty"`
	RecipientAccountId  string                 `json:"recipientAccountId"`
	ServiceEventDetails map[string]interface{} `json:"serviceEventDetails,omitempty"`
}

// CloudTrailUserIdentity represents the user identity in CloudTrail
type CloudTrailUserIdentity struct {
	Type           string                    `json:"type"`
	PrincipalId    string                    `json:"principalId"`
	ARN            string                    `json:"arn"`
	AccountId      string                    `json:"accountId"`
	UserName       string                    `json:"userName,omitempty"`
	AccessKeyId    string                    `json:"accessKeyId,omitempty"`
	SessionContext *CloudTrailSessionContext `json:"sessionContext,omitempty"`
}

// CloudTrailSessionContext represents session context
type CloudTrailSessionContext struct {
	SessionIssuer    CloudTrailSessionIssuer `json:"sessionIssuer"`
	CreationDate     time.Time               `json:"creationDate"`
	MFAAuthenticated bool                    `json:"mfaAuthenticated"`
}

// CloudTrailSessionIssuer represents session issuer
type CloudTrailSessionIssuer struct {
	Type        string `json:"type"`
	PrincipalId string `json:"principalId"`
	ARN         string `json:"arn"`
	UserName    string `json:"userName"`
}

// CloudTrailResource represents a resource in CloudTrail
type CloudTrailResource struct {
	AccountId string `json:"accountId"`
	Type      string `json:"type"`
	ARN       string `json:"ARN"`
}

// Collector implements CloudTrail event collection
type Collector struct {
	config     *config.CloudTrailConfig
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

	// Tracking for change detection
	lastProcessed time.Time
}

// NewCollector creates a new CloudTrail collector
func NewCollector(cfg *config.CloudTrailConfig, awsManager *awsClient.ClientManager) (*Collector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if awsManager == nil {
		return nil, fmt.Errorf("AWS manager is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component":     "cloudtrail_collector",
		"s3_bucket":     cfg.S3Bucket,
		"poll_interval": cfg.PollInterval,
	})

	collector := &Collector{
		config:        cfg,
		awsManager:    awsManager,
		logger:        logger,
		eventsChan:    make(chan sentinelTypes.Event, 1000),
		subscribers:   make([]chan sentinelTypes.Event, 0),
		lastProcessed: time.Now().Add(-cfg.LookbackTime),
		health: sentinelTypes.CollectorHealth{
			Status:      string(sentinelTypes.HealthStatusStopped),
			Performance: sentinelTypes.PerformanceStats{},
		},
	}

	logger.Info("CloudTrail collector created")
	return collector, nil
}

// Name returns the collector name
func (c *Collector) Name() string {
	return "cloudtrail"
}

// Start begins the CloudTrail collection process
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector is already running")
	}

	c.logger.Info("Starting CloudTrail collector")
	c.running = true
	c.startTime = time.Now()
	c.health.Status = string(sentinelTypes.HealthStatusHealthy)
	c.health.LastCollection = time.Now()

	// Start collection goroutine
	go c.collectLoop(ctx)

	// Start event distribution goroutine
	go c.distributeEvents(ctx)

	c.logger.Info("CloudTrail collector started successfully")
	return nil
}

// Stop gracefully stops the collector
func (c *Collector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.logger.Info("Stopping CloudTrail collector")
	c.running = false
	c.health.Status = string(sentinelTypes.HealthStatusStopped)

	// Close events channel
	close(c.eventsChan)

	c.logger.Info("CloudTrail collector stopped")
	return nil
}

// Collect performs a single collection cycle (for manual triggering)
func (c *Collector) Collect(ctx context.Context) ([]sentinelTypes.Event, error) {
	if !c.config.Enabled {
		return nil, nil
	}

	startTime := time.Now()
	events, err := c.fetchCloudTrailEvents(ctx)
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
	ticker := time.NewTicker(c.config.PollInterval)
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
		c.logger.WithError(err).Error("Initial CloudTrail collection failed")
	}

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("CloudTrail collection loop stopping")
			return
		case <-ticker.C:
			if !c.isRunning() {
				return
			}

			events, err := c.Collect(ctx)
			if err != nil {
				c.logger.WithError(err).Error("Failed to collect CloudTrail events")
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
			c.logger.Info("CloudTrail event distribution stopping")
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

// fetchCloudTrailEvents retrieves and processes CloudTrail events
func (c *Collector) fetchCloudTrailEvents(ctx context.Context) ([]sentinelTypes.Event, error) {
	s3Client := c.awsManager.S3()

	// Calculate the time window based on LookbackTime
	now := time.Now()
	lookbackStartTime := now.Add(-c.config.LookbackTime)

	// Use the later of lastProcessed or lookbackStartTime to avoid duplicates
	// but ensure we don't miss events within the lookback window
	effectiveStartTime := c.lastProcessed
	if lookbackStartTime.After(c.lastProcessed) {
		effectiveStartTime = lookbackStartTime
	}

	// List recent CloudTrail log files with pagination
	// Note: AWS S3 ListObjectsV2 has a limit of 1000 objects per request.
	// We need to paginate to ensure we don't miss events within our lookback time window.
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(c.config.S3Bucket),
		Prefix: aws.String(c.config.S3Prefix),
	}

	var events []sentinelTypes.Event
	var objectsProcessed int
	var skippedOld int
	var skippedFuture int
	var totalObjects int
	var pagesProcessed int

	// Paginate through all objects to ensure we capture all events within the lookback window
	for {
		result, err := s3Client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list CloudTrail objects: %w", err)
		}

		pagesProcessed++
		totalObjects += len(result.Contents)

		// Process each object in this page
		for _, obj := range result.Contents {
			// Skip objects that are older than our effective start time
			if obj.LastModified.Before(effectiveStartTime) {
				skippedOld++
				continue
			}

			// Also skip objects that are too new (future events)
			if obj.LastModified.After(now) {
				skippedFuture++
				continue
			}

			// Only process CloudTrail log files (they have .json.gz extension)
			if !strings.HasSuffix(*obj.Key, ".json.gz") {
				continue
			}

			objectsProcessed++

			// Parse the actual CloudTrail log file
			logEvents, err := c.processCloudTrailLogFile(ctx, *obj.Key)
			if err != nil {
				c.logger.WithFields(logrus.Fields{
					"object_key": *obj.Key,
					"error":      err,
				}).Error("Failed to process CloudTrail log file")
				continue
			}

			events = append(events, logEvents...)
		}

		// Check if we need to continue pagination
		if !*result.IsTruncated {
			break
		}

		// Set continuation token for next page
		input.ContinuationToken = result.NextContinuationToken
	}

	// Update last processed time to current time
	c.mu.Lock()
	c.lastProcessed = now
	c.mu.Unlock()

	c.logger.WithFields(logrus.Fields{
		"total_objects":     totalObjects,
		"pages_processed":   pagesProcessed,
		"objects_processed": objectsProcessed,
		"skipped_old":       skippedOld,
		"skipped_future":    skippedFuture,
		"events_found":      len(events),
		"time_window":       c.config.LookbackTime,
	}).Debug("CloudTrail collection completed")

	return events, nil
}

// processCloudTrailLogFile downloads and processes a single CloudTrail log file
func (c *Collector) processCloudTrailLogFile(ctx context.Context, objectKey string) ([]sentinelTypes.Event, error) {
	// Download the log file from S3
	logData, err := c.downloadAndDecompressLogFile(ctx, objectKey)
	if err != nil {
		return nil, fmt.Errorf("failed to download log file %s: %w", objectKey, err)
	}

	// Parse the JSON content
	var cloudTrailRecord CloudTrailLogRecord
	if err := json.Unmarshal(logData, &cloudTrailRecord); err != nil {
		return nil, fmt.Errorf("failed to parse CloudTrail log %s: %w", objectKey, err)
	}

	var events []sentinelTypes.Event
	var filteredEvents int

	// Process each record in the log file
	for _, record := range cloudTrailRecord.Records {
		// Filter events based on configured event names
		if c.shouldProcessEvent(record.EventName) {
			resourcesInvolved := []string{}
			for _, resource := range record.Resources {
				resourcesInvolved = append(resourcesInvolved, resource.ARN)
			}
			c.logger.WithFields(logrus.Fields{
				"event_name":         record.EventName,
				"resources_involved": resourcesInvolved,
			}).Debug("Processing CloudTrail record")
			event := c.convertCloudTrailRecord(record, objectKey)
			events = append(events, event)
			filteredEvents++
		}
	}

	// c.logger.WithFields(logrus.Fields{
	// 	"object_key":       objectKey,
	// 	"total_records":    len(cloudTrailRecord.Records),
	// 	"filtered_events":  filteredEvents,
	// 	"configured_names": c.config.EventNames,
	// }).Debug("Processed CloudTrail log file")

	return events, nil
}

// downloadAndDecompressLogFile downloads and decompresses a CloudTrail log file from S3
func (c *Collector) downloadAndDecompressLogFile(ctx context.Context, objectKey string) ([]byte, error) {
	s3Client := c.awsManager.S3()

	// Download the file from S3
	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.config.S3Bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer result.Body.Close()

	// Decompress the gzipped content
	gzReader, err := gzip.NewReader(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Read all decompressed data
	data, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	return data, nil
}

// shouldProcessEvent checks if an event should be processed based on configured event names
func (c *Collector) shouldProcessEvent(eventName string) bool {
	// If no event names are configured, process all events
	if len(c.config.EventNames) == 0 {
		return true
	}

	// Check if this event is in our configured event_names list
	for _, configuredEvent := range c.config.EventNames {
		if eventName == configuredEvent {
			return true
		}
	}
	return false
}

// convertCloudTrailRecord converts a CloudTrail record to a Sentinel event
func (c *Collector) convertCloudTrailRecord(record CloudTrailRecord, sourceObject string) sentinelTypes.Event {
	// Convert user identity
	userIdentity := sentinelTypes.UserIdentity{
		Type:        record.UserIdentity.Type,
		PrincipalId: record.UserIdentity.PrincipalId,
		UserName:    record.UserIdentity.UserName,
		ARN:         record.UserIdentity.ARN,
		AccountId:   record.UserIdentity.AccountId,
		AccessKeyId: record.UserIdentity.AccessKeyId,
	}

	// Convert session context if present
	if record.UserIdentity.SessionContext != nil {
		userIdentity.SessionContext = &sentinelTypes.SessionContext{
			CreationDate:     record.UserIdentity.SessionContext.CreationDate.Unix(),
			MFAAuthenticated: record.UserIdentity.SessionContext.MFAAuthenticated,
			SessionIssuer: sentinelTypes.SessionIssuer{
				Type:        record.UserIdentity.SessionContext.SessionIssuer.Type,
				PrincipalId: record.UserIdentity.SessionContext.SessionIssuer.PrincipalId,
				ARN:         record.UserIdentity.SessionContext.SessionIssuer.ARN,
				UserName:    record.UserIdentity.SessionContext.SessionIssuer.UserName,
			},
		}
	}

	// Extract resource name from request parameters
	resourceName := c.extractResourceName(record.RequestParameters, record.EventName)

	cloudTrailEvent := sentinelTypes.CloudTrailEvent{
		EventID:          record.EventID,
		EventName:        record.EventName,
		EventTime:        record.EventTime.Unix(),
		EventSource:      record.EventSource,
		EventVersion:     record.EventVersion,
		AWSRegion:        record.AWSRegion,
		SourceIP:         record.SourceIPAddress,
		UserAgent:        record.UserAgent,
		RequestParams:    record.RequestParameters,
		ResponseElements: record.ResponseElements,
		ReadOnly:         record.ReadOnly,
		ResourceName:     resourceName,
		ErrorCode:        record.ErrorCode,
		ErrorMessage:     record.ErrorMessage,
		UserIdentity:     userIdentity,
	}

	event := sentinelTypes.Event{
		ID:         record.EventID,
		Type:       sentinelTypes.EventTypeCloudTrail,
		Timestamp:  record.EventTime,
		Source:     "cloudtrail_collector",
		CloudTrail: &cloudTrailEvent,
	}

	return event
}

// extractResourceName extracts the primary resource name from request parameters
func (c *Collector) extractResourceName(requestParams map[string]interface{}, eventName string) string {
	if requestParams == nil {
		return ""
	}

	// Common resource identifiers in priority order (most specific first)
	resourceKeys := []string{
		"dBClusterSnapshotIdentifier", // Cluster snapshots are most specific
		"dBSnapshotIdentifier",        // Instance snapshots are more specific than instances
		"dBClusterIdentifier",         // Aurora clusters are specific
		"sourceDBClusterIdentifier",   // Source cluster for operations
		"targetDBClusterIdentifier",   // Target cluster for operations  
		"dBClusterEndpointIdentifier", // Cluster endpoints
		"globalClusterIdentifier",     // Global clusters
		"readReplicaDBInstanceIdentifier",
		"sourceDBInstanceIdentifier",
		"targetDBInstanceIdentifier",
		"dBInstanceIdentifier", // General instance identifier
	}

	// Try to find a resource identifier
	for _, key := range resourceKeys {
		if value, exists := requestParams[key]; exists {
			if strValue, ok := value.(string); ok && strValue != "" {
				return strValue
			}
		}
	}

	// Fallback: return the event name as resource identifier
	return eventName
}

// isRunning returns whether the collector is currently running
func (c *Collector) isRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}
