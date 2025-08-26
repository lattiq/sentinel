package processor

import (
	"context"
	"crypto/md5"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/pkg/types"
	"github.com/lattiq/sentinel/version"
)

// EventProcessor implements the event processing pipeline
type EventProcessor struct {
	config    *config.Config
	logger    *logrus.Entry
	batcher   *Batcher
	validator *MessageValidator

	// Metrics
	processedEvents int64
	errorCount      int64
	lastProcessTime time.Time
}

// New creates a new event processor
func New(cfg *config.Config) (*EventProcessor, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component": "event_processor",
		"client_id": cfg.Client.ID,
	})

	batcher := NewBatcher(&cfg.Batch, logger)
	validator := NewMessageValidator(logger)

	processor := &EventProcessor{
		config:    cfg,
		logger:    logger,
		batcher:   batcher,
		validator: validator,
	}

	logger.Info("Event processor created")
	return processor, nil
}

// Process converts raw events to monitoring messages
func (p *EventProcessor) Process(ctx context.Context, events []types.Event) ([]types.MonitoringMessage, error) {
	if len(events) == 0 {
		return nil, nil
	}

	// [START DEBUGGER] flush the events into a json file for debugging
	// jsonData, err := json.Marshal(events)
	// if err != nil {
	// 	p.logger.WithError(err).Error("Failed to marshal events to JSON")
	// }
	// os.WriteFile(fmt.Sprintf("events-%d.json", time.Now().Unix()), jsonData, 0644)
	// [END DEBUGGER]

	p.logger.WithField("event_count", len(events)).Debug("Processing events")
	startTime := time.Now()

	var messages []types.MonitoringMessage
	var errors []error

	for _, event := range events {
		message, err := p.processEvent(event)
		if err != nil {
			p.errorCount++
			p.logger.WithError(err).WithField("event_id", event.ID).Error("Failed to process event")
			errors = append(errors, err)
			continue
		}

		if message != nil {
			// Validate the message
			if err := p.validator.Validate(*message); err != nil {
				p.errorCount++
				p.logger.WithError(err).WithField("message_id", message.MessageID).Error("Message validation failed")
				errors = append(errors, err)
				continue
			}

			messages = append(messages, *message)
		}
	}

	// Update metrics
	p.processedEvents += int64(len(events))
	p.lastProcessTime = time.Now()
	processingDuration := time.Since(startTime)

	p.logger.WithFields(logrus.Fields{
		"events_processed": len(events),
		"messages_created": len(messages),
		"errors":           len(errors),
		"duration_ms":      processingDuration.Milliseconds(),
	}).Debug("Event processing completed")

	// Return error if all events failed
	if len(messages) == 0 && len(errors) > 0 {
		return nil, fmt.Errorf("failed to process any events: %d errors", len(errors))
	}

	return messages, nil
}

// processEvent converts a single event to a monitoring message
func (p *EventProcessor) processEvent(event types.Event) (*types.MonitoringMessage, error) {
	switch event.Type {
	case types.EventTypeQueryLog:
		return p.processQueryLogEvent(event)
	case types.EventTypeRDSInstance:
		return p.processRDSInstanceEvent(event)
	case types.EventTypeRDSCluster:
		return p.processRDSClusterEvent(event)
	case types.EventTypeRDSConfig:
		return p.processRDSConfigEvent(event)
	case types.EventTypeRDSSnapshot:
		return p.processRDSSnapshotEvent(event)
	case types.EventTypeCloudTrail:
		return p.processCloudTrailEvent(event)
	case types.EventTypeHealth:
		return p.processHealthEvent(event)
	case types.EventTypeAgentHealth:
		return p.processAgentHealthEvent(event)
	case types.EventTypeConfig:
		return p.processConfigEvent(event)
	default:
		return nil, fmt.Errorf("unsupported event type: %s", event.Type)
	}
}

// processQueryLogEvent processes query log events
func (p *EventProcessor) processQueryLogEvent(event types.Event) (*types.MonitoringMessage, error) {
	if event.QueryLog == nil {
		// Try to extract from Data field for backward compatibility
		if data, ok := event.Data.(map[string]interface{}); ok {
			if parsedEvent, exists := data["parsed_event"]; exists {
				return p.createQueryLogMessage(event, parsedEvent)
			}
		}
		return nil, fmt.Errorf("query log event data is missing")
	}

	return p.createQueryLogMessage(event, event.QueryLog)
}

// processRDSInstanceEvent processes RDS instance events
func (p *EventProcessor) processRDSInstanceEvent(event types.Event) (*types.MonitoringMessage, error) {
	if event.RDSInstance == nil {
		return nil, fmt.Errorf("RDS instance event data is missing")
	}

	return p.createRDSInstanceMessage(event, event.RDSInstance)
}

// processRDSClusterEvent processes RDS cluster events
func (p *EventProcessor) processRDSClusterEvent(event types.Event) (*types.MonitoringMessage, error) {
	if event.RDSCluster == nil {
		return nil, fmt.Errorf("RDS cluster event data is missing")
	}

	return p.createRDSClusterMessage(event, event.RDSCluster)
}

// processRDSConfigEvent processes RDS config events
func (p *EventProcessor) processRDSConfigEvent(event types.Event) (*types.MonitoringMessage, error) {
	if event.RDSConfig == nil {
		return nil, fmt.Errorf("RDS config event data is missing")
	}

	return p.createRDSConfigMessage(event, event.RDSConfig)
}

// processRDSSnapshotEvent processes RDS snapshot events
func (p *EventProcessor) processRDSSnapshotEvent(event types.Event) (*types.MonitoringMessage, error) {
	if event.RDSSnapshot == nil {
		return nil, fmt.Errorf("RDS snapshot event data is missing")
	}

	return p.createRDSSnapshotMessage(event, event.RDSSnapshot)
}

// processCloudTrailEvent processes CloudTrail events
func (p *EventProcessor) processCloudTrailEvent(event types.Event) (*types.MonitoringMessage, error) {
	if event.CloudTrail == nil {
		return nil, fmt.Errorf("CloudTrail event data is missing")
	}

	return p.createCloudTrailMessage(event, event.CloudTrail)
}

// processHealthEvent processes health events
func (p *EventProcessor) processHealthEvent(event types.Event) (*types.MonitoringMessage, error) {
	if event.Health == nil {
		return nil, fmt.Errorf("health event data is missing")
	}

	return p.createHealthMessage(event, event.Health)
}

// processAgentHealthEvent processes agent health events
func (p *EventProcessor) processAgentHealthEvent(event types.Event) (*types.MonitoringMessage, error) {
	if event.AgentHealth == nil {
		return nil, fmt.Errorf("agent health event data is missing")
	}

	return p.createAgentHealthMessage(event, event.AgentHealth)
}

// processConfigEvent processes config events
func (p *EventProcessor) processConfigEvent(event types.Event) (*types.MonitoringMessage, error) {
	if event.Config == nil {
		return nil, fmt.Errorf("config event data is missing")
	}

	return p.createConfigMessage(event, event.Config)
}

// createQueryLogMessage creates a monitoring message for query log events
func (p *EventProcessor) createQueryLogMessage(event types.Event, data interface{}) (*types.MonitoringMessage, error) {
	message := &types.MonitoringMessage{
		MessageID:   p.generateMessageID(event),
		ClientID:    p.config.Client.ID,
		Timestamp:   event.Timestamp.Unix(),
		MessageType: types.MessageTypeQueryLogs,
		BatchSize:   1,
		Data:        data,
		Metadata: map[string]interface{}{
			"source":      event.Source,
			"event_id":    event.ID,
			"collector":   "query_logs",
			"environment": p.config.Client.Environment,
		},
		Version: version.Version(),
	}

	return message, nil
}

// createRDSInstanceMessage creates a monitoring message for RDS instance events
func (p *EventProcessor) createRDSInstanceMessage(event types.Event, data *types.RDSInstanceEvent) (*types.MonitoringMessage, error) {
	message := &types.MonitoringMessage{
		MessageID:   p.generateMessageID(event),
		ClientID:    p.config.Client.ID,
		Timestamp:   event.Timestamp.Unix(),
		MessageType: types.MessageTypeRDSInstances,
		BatchSize:   1,
		Data:        data,
		Metadata: map[string]interface{}{
			"source":      event.Source,
			"event_id":    event.ID,
			"collector":   "rds_instances",
			"instance_id": data.InstanceID,
			"environment": p.config.Client.Environment,
		},
		Version: version.Version(),
	}

	return message, nil
}

// createRDSClusterMessage creates a monitoring message for RDS cluster events
func (p *EventProcessor) createRDSClusterMessage(event types.Event, data *types.RDSClusterEvent) (*types.MonitoringMessage, error) {
	message := &types.MonitoringMessage{
		MessageID:   p.generateMessageID(event),
		ClientID:    p.config.Client.ID,
		Timestamp:   event.Timestamp.Unix(),
		MessageType: types.MessageTypeRDSClusters,
		BatchSize:   1,
		Data:        data,
		Metadata: map[string]interface{}{
			"source":      event.Source,
			"event_id":    event.ID,
			"collector":   "rds_clusters",
			"cluster_id":  data.ClusterID,
			"engine":      data.Engine,
			"status":      data.Status,
			"environment": p.config.Client.Environment,
		},
		Version: version.Version(),
	}

	return message, nil
}

// createRDSConfigMessage creates a monitoring message for RDS config events
func (p *EventProcessor) createRDSConfigMessage(event types.Event, data *types.RDSConfigEvent) (*types.MonitoringMessage, error) {
	message := &types.MonitoringMessage{
		MessageID:   p.generateMessageID(event),
		ClientID:    p.config.Client.ID,
		Timestamp:   event.Timestamp.Unix(),
		MessageType: types.MessageTypeRDSConfig,
		BatchSize:   1,
		Data:        data,
		Metadata: map[string]interface{}{
			"source":      event.Source,
			"event_id":    event.ID,
			"collector":   "rds_configs",
			"instance_id": data.InstanceID,
			"environment": p.config.Client.Environment,
		},
		Version: version.Version(),
	}

	return message, nil
}

// createRDSSnapshotMessage creates a monitoring message for RDS snapshot events
func (p *EventProcessor) createRDSSnapshotMessage(event types.Event, data *types.RDSSnapshotEvent) (*types.MonitoringMessage, error) {
	message := &types.MonitoringMessage{
		MessageID:   p.generateMessageID(event),
		ClientID:    p.config.Client.ID,
		Timestamp:   event.Timestamp.Unix(),
		MessageType: types.MessageTypeRDSSnapshots,
		BatchSize:   1,
		Data:        data,
		Metadata: map[string]interface{}{
			"source":      event.Source,
			"event_id":    event.ID,
			"collector":   "rds_snapshots",
			"snapshot_id": data.SnapshotID,
			"instance_id": data.InstanceID,
			"environment": p.config.Client.Environment,
		},
		Version: version.Version(),
	}

	return message, nil
}

// createCloudTrailMessage creates a monitoring message for CloudTrail events
func (p *EventProcessor) createCloudTrailMessage(event types.Event, data *types.CloudTrailEvent) (*types.MonitoringMessage, error) {
	message := &types.MonitoringMessage{
		MessageID:   p.generateMessageID(event),
		ClientID:    p.config.Client.ID,
		Timestamp:   event.Timestamp.Unix(),
		MessageType: types.MessageTypeCloudTrail,
		BatchSize:   1,
		Data:        data,
		Metadata: map[string]interface{}{
			"source":      event.Source,
			"event_id":    event.ID,
			"collector":   "cloudtrail",
			"event_name":  data.EventName,
			"environment": p.config.Client.Environment,
		},
		Version: version.Version(),
	}

	return message, nil
}

// createHealthMessage creates a monitoring message for health events
func (p *EventProcessor) createHealthMessage(event types.Event, data *types.HealthEvent) (*types.MonitoringMessage, error) {
	message := &types.MonitoringMessage{
		MessageID:   p.generateMessageID(event),
		ClientID:    p.config.Client.ID,
		Timestamp:   event.Timestamp.Unix(),
		MessageType: types.MessageTypeHealth,
		BatchSize:   1,
		Data:        data,
		Metadata: map[string]interface{}{
			"source":      event.Source,
			"event_id":    event.ID,
			"collector":   "health",
			"status":      data.Status,
			"environment": p.config.Client.Environment,
		},
		Version: version.Version(),
	}

	return message, nil
}

// createAgentHealthMessage creates a monitoring message for agent health events
func (p *EventProcessor) createAgentHealthMessage(event types.Event, data *types.AgentHealthEvent) (*types.MonitoringMessage, error) {
	message := &types.MonitoringMessage{
		MessageID:   p.generateMessageID(event),
		ClientID:    p.config.Client.ID,
		Timestamp:   event.Timestamp.Unix(),
		MessageType: types.MessageTypeAgentHealth,
		BatchSize:   1,
		Data:        data,
		Metadata: map[string]interface{}{
			"source":        event.Source,
			"event_id":      event.ID,
			"collector":     "agent_health",
			"agent_version": data.AgentVersion,
			"status":        data.Status,
			"environment":   p.config.Client.Environment,
		},
		Version: version.Version(),
	}

	return message, nil
}

// createConfigMessage creates a monitoring message for config events
func (p *EventProcessor) createConfigMessage(event types.Event, data *types.ConfigEvent) (*types.MonitoringMessage, error) {
	message := &types.MonitoringMessage{
		MessageID:   p.generateMessageID(event),
		ClientID:    p.config.Client.ID,
		Timestamp:   event.Timestamp.Unix(),
		MessageType: types.MessageTypeConfig,
		BatchSize:   1,
		Data:        data,
		Metadata: map[string]interface{}{
			"source":      event.Source,
			"event_id":    event.ID,
			"collector":   "config",
			"environment": p.config.Client.Environment,
		},
		Version: version.Version(),
	}

	return message, nil
}

// generateMessageID generates a unique message ID
func (p *EventProcessor) generateMessageID(event types.Event) string {
	data := fmt.Sprintf("%s-%s-%d-%s",
		p.config.Client.ID,
		event.ID,
		event.Timestamp.UnixNano(),
		event.Source,
	)
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// Validate validates a monitoring message
func (p *EventProcessor) Validate(message types.MonitoringMessage) error {
	return p.validator.Validate(message)
}

// GetMetrics returns processing metrics
func (p *EventProcessor) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"processed_events":  p.processedEvents,
		"error_count":       p.errorCount,
		"last_process_time": p.lastProcessTime,
	}
}
