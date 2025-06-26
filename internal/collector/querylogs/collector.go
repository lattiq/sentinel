package querylogs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/sirupsen/logrus"

	"github.com/lattiq/sentinel/internal/analyzer"
	awsClient "github.com/lattiq/sentinel/internal/aws"
	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/internal/parser"
	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

// LogParser interface is now defined in the parser package

// Collector implements query log collection from CloudWatch Logs
type Collector struct {
	config          *config.QueryLogsConfig
	awsManager      *awsClient.ClientManager
	parser          parser.LogParser
	patternDetector *analyzer.PatternDetector
	logger          *logrus.Entry

	// State management
	mu        sync.RWMutex
	running   bool
	lastToken string
	startTime time.Time

	// Event distribution
	eventsChan  chan sentinelTypes.Event
	subscribers []chan sentinelTypes.Event

	// Health metrics
	health          sentinelTypes.CollectorHealth
	eventsCollected int64
	errorsCount     int64
	lastError       string
}

// New creates a new query logs collector
func New(cfg *config.QueryLogsConfig, awsManager *awsClient.ClientManager, features map[string][]string) (*Collector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if awsManager == nil {
		return nil, fmt.Errorf("AWS manager is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component":  "query_logs_collector",
		"log_group":  cfg.LogGroup,
		"batch_size": cfg.BatchSize,
	})

	// Create enhanced PostgreSQL parser for better abuse detection
	logParser := parser.NewPostgreSQLParser(cfg, features)

	// Create pattern detector for systematic attack detection
	patternDetector := analyzer.NewPatternDetector()

	collector := &Collector{
		config:          cfg,
		awsManager:      awsManager,
		parser:          logParser,
		patternDetector: patternDetector,
		logger:          logger,
		eventsChan:      make(chan sentinelTypes.Event, 1000),
		subscribers:     make([]chan sentinelTypes.Event, 0),
		health: sentinelTypes.CollectorHealth{
			Status:      string(sentinelTypes.HealthStatusStopped),
			Performance: sentinelTypes.PerformanceStats{},
		},
	}

	logger.Info("Query logs collector created with enhanced PostgreSQL parser and pattern detector")
	return collector, nil
}

// NewWithConfig creates a new database-aware query logs collector
func NewWithConfig(fullConfig *config.Config, awsManager *awsClient.ClientManager) (*Collector, error) {
	cfg := &fullConfig.DataSources.QueryLogs
	if cfg == nil {
		return nil, fmt.Errorf("query logs configuration is required")
	}
	if awsManager == nil {
		return nil, fmt.Errorf("AWS manager is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component":      "query_logs_collector",
		"log_group":      cfg.LogGroup,
		"batch_size":     cfg.BatchSize,
		"database_aware": true,
	})

	// Create database-aware PostgreSQL parser
	logParser := parser.NewPostgreSQLParserWithConfig(fullConfig)

	// Create pattern detector for systematic attack detection
	patternDetector := analyzer.NewPatternDetector()

	collector := &Collector{
		config:          cfg,
		awsManager:      awsManager,
		parser:          logParser,
		patternDetector: patternDetector,
		logger:          logger,
		eventsChan:      make(chan sentinelTypes.Event, 1000),
		subscribers:     make([]chan sentinelTypes.Event, 0),
		health: sentinelTypes.CollectorHealth{
			Status:      string(sentinelTypes.HealthStatusStopped),
			Performance: sentinelTypes.PerformanceStats{},
		},
	}

	logger.Info("Query logs collector created with database-aware PostgreSQL parser and pattern detector")
	return collector, nil
}

// Name returns the collector name
func (c *Collector) Name() string {
	return "query_logs"
}

// Start begins the query log collection process
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector is already running")
	}

	c.logger.Info("Starting query logs collector")
	c.running = true
	c.startTime = time.Now()
	c.health.Status = string(sentinelTypes.HealthStatusHealthy)
	c.health.LastCollection = time.Now()

	// Initialize start time for log collection
	if err := c.initializeStartTime(); err != nil {
		c.running = false
		c.health.Status = string(sentinelTypes.HealthStatusError)
		return fmt.Errorf("failed to initialize start time: %w", err)
	}

	// Start collection goroutine
	go c.collectLoop(ctx)

	// Start event distribution goroutine
	go c.distributeEvents(ctx)

	c.logger.Info("Query logs collector started successfully")
	return nil
}

// Stop gracefully stops the collector
func (c *Collector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.logger.Info("Stopping query logs collector")
	c.running = false
	c.health.Status = string(sentinelTypes.HealthStatusStopped)

	// Close events channel
	close(c.eventsChan)

	c.logger.Info("Query logs collector stopped")
	return nil
}

// Collect performs a single collection cycle (for manual triggering)
func (c *Collector) Collect(ctx context.Context) ([]sentinelTypes.Event, error) {
	if !c.config.Enabled {
		return nil, nil
	}

	startTime := time.Now()
	events, err := c.fetchLogEvents(ctx)
	duration := time.Since(startTime)

	// Update health metrics
	c.mu.Lock()
	c.health.LastCollection = time.Now()
	c.health.Performance.AvgLatency = duration
	c.health.Performance.LastUpdated = time.Now()

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

// initializeStartTime sets up the initial start time for log collection
func (c *Collector) initializeStartTime() error {
	switch c.config.StartTime {
	case "latest":
		// Start from current time
		c.lastToken = ""
	case "earliest":
		// Start from beginning (this could be expensive)
		c.lastToken = ""
	default:
		// Try to parse as ISO timestamp
		if startTime, err := time.Parse(time.RFC3339, c.config.StartTime); err == nil {
			// Convert to Unix timestamp in milliseconds for CloudWatch
			_ = startTime.UnixMilli()
			c.lastToken = ""
		} else {
			return fmt.Errorf("invalid start_time format: %s", c.config.StartTime)
		}
	}
	return nil
}

// collectLoop runs the continuous log collection
func (c *Collector) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.PollInterval)
	defer ticker.Stop()

	c.logger.Debug("Starting collection loop")

	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("Collection loop stopped by context")
			return
		case <-ticker.C:
			if !c.isRunning() {
				return
			}

			events, err := c.Collect(ctx)
			if err != nil {
				c.logger.WithError(err).Error("Failed to collect log events")
				continue
			}

			// Send events to distribution channel
			for _, event := range events {
				select {
				case c.eventsChan <- event:
					// Event sent successfully
				case <-ctx.Done():
					return
				default:
					c.logger.Warn("Events channel is full, dropping event")
				}
			}

			if len(events) > 0 {
				c.logger.WithField("event_count", len(events)).Debug("Collected log events")
			}
		}
	}
}

// distributeEvents distributes events to all subscribers
func (c *Collector) distributeEvents(ctx context.Context) {
	for {
		select {
		case event, ok := <-c.eventsChan:
			if !ok {
				// Channel closed, clean up subscribers
				c.mu.Lock()
				for _, subscriber := range c.subscribers {
					close(subscriber)
				}
				c.subscribers = nil
				c.mu.Unlock()
				return
			}

			// Send to all subscribers
			c.mu.RLock()
			for _, subscriber := range c.subscribers {
				select {
				case subscriber <- event:
					// Event sent successfully
				case <-ctx.Done():
					c.mu.RUnlock()
					return
				default:
					// Subscriber channel is full, skip this subscriber
					c.logger.Warn("Subscriber channel is full, dropping event")
				}
			}
			c.mu.RUnlock()

		case <-ctx.Done():
			return
		}
	}
}

// fetchLogEvents retrieves log events from CloudWatch Logs
func (c *Collector) fetchLogEvents(ctx context.Context) ([]sentinelTypes.Event, error) {
	client := c.awsManager.CloudWatchLogs()

	// Prepare input for filtering log events
	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(c.config.LogGroup),
		Limit:        aws.Int32(int32(c.config.BatchSize)),
	}

	// Add stream names if specified
	if len(c.config.StreamNames) > 0 {
		input.LogStreamNames = c.config.StreamNames
	}

	// Add filter pattern if specified
	if c.config.FilterPattern != "" {
		input.FilterPattern = aws.String(c.config.FilterPattern)
	}

	// Add next token for pagination
	if c.lastToken != "" {
		input.NextToken = aws.String(c.lastToken)
	}

	// Set start time (look back a bit to avoid missing events)
	switch c.config.StartTime {
	case "latest":
		startTime := time.Now().Add(-5 * time.Minute).UnixMilli()
		input.StartTime = aws.Int64(startTime)
	case "earliest":
		// Don't set StartTime to get logs from the beginning
		// This will retrieve all available logs (potentially expensive)
	default:
		// Try to parse as ISO timestamp
		if startTime, err := time.Parse(time.RFC3339, c.config.StartTime); err == nil {
			input.StartTime = aws.Int64(startTime.UnixMilli())
		} else {
			c.logger.WithField("start_time", c.config.StartTime).Warn("Invalid start_time format, using latest")
			startTime := time.Now().Add(-5 * time.Minute).UnixMilli()
			input.StartTime = aws.Int64(startTime)
		}
	}

	// Execute the request
	output, err := client.FilterLogEvents(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to filter log events: %w", err)
	}

	// Update next token for pagination
	if output.NextToken != nil {
		c.lastToken = *output.NextToken
	}

	// Convert CloudWatch events to our event format
	events := make([]sentinelTypes.Event, 0, len(output.Events))
	for _, logEvent := range output.Events {
		event, err := c.convertLogEvent(logEvent)
		if err != nil {
			c.logger.WithError(err).Warn("Failed to convert log event")
			continue
		}
		if event != nil {
			events = append(events, *event)
		}
	}

	return events, nil
}

// convertLogEvent converts a CloudWatch log event to our internal event format
func (c *Collector) convertLogEvent(logEvent types.FilteredLogEvent) (*sentinelTypes.Event, error) {
	if logEvent.Message == nil {
		return nil, nil
	}

	// Parse the log message using our parser
	parsedEvent, err := c.parser.ParseLogMessage(
		*logEvent.Message,
		*logEvent.LogStreamName,
		time.UnixMilli(*logEvent.Timestamp),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log message: %w", err)
	}

	if parsedEvent == nil {
		return nil, nil
	}

	// Analyze for potential data abuse
	analysis := c.parser.AnalyzeForAbuse(parsedEvent)

	// Perform pattern analysis for systematic attacks
	patternAnalysis := c.patternDetector.AnalyzeQuery(parsedEvent)

	// Combine risk scores
	totalRiskScore := analysis.RiskScore + patternAnalysis.RiskScore

	// Log high-risk events
	if totalRiskScore > 50.0 {
		c.logger.WithFields(logrus.Fields{
			"user":                parsedEvent.UserName,
			"database":            parsedEvent.DatabaseName,
			"query_type":          parsedEvent.QueryType,
			"risk_score":          analysis.RiskScore,
			"pattern_score":       patternAnalysis.RiskScore,
			"total_score":         totalRiskScore,
			"patterns":            analysis.SuspiciousPattern,
			"systematic_patterns": patternAnalysis.SuspiciousPatterns,
			"confidence":          patternAnalysis.Confidence,
			"client_ip":           parsedEvent.ClientIP,
			"duration":            parsedEvent.Duration,
		}).Warn("High-risk database activity detected")
	}

	// Create basic event structure
	event := &sentinelTypes.Event{
		ID:        fmt.Sprintf("log-%s", *logEvent.EventId),
		Type:      sentinelTypes.EventTypeQueryLog,
		Timestamp: time.UnixMilli(*logEvent.Timestamp),
		Source:    "cloudwatch_logs",
		Data: map[string]interface{}{
			"raw_message":      *logEvent.Message,
			"log_stream":       *logEvent.LogStreamName,
			"ingestion_time":   *logEvent.IngestionTime,
			"parsed_event":     parsedEvent,
			"analysis":         analysis,
			"pattern_analysis": patternAnalysis,
			"total_risk_score": totalRiskScore,
		},
	}

	return event, nil
}

// isRunning safely checks if the collector is running
func (c *Collector) isRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}
