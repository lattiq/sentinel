package processor

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/lattiq/sentinel/pkg/types"
)

// MessageValidator validates monitoring messages
type MessageValidator struct {
	logger *logrus.Entry
}

// NewMessageValidator creates a new message validator
func NewMessageValidator(logger *logrus.Entry) *MessageValidator {
	return &MessageValidator{
		logger: logger.WithField("component", "validator"),
	}
}

// Validate validates a monitoring message according to the agent-service contract
func (v *MessageValidator) Validate(message types.MonitoringMessage) error {
	// Validate required fields
	if err := v.validateRequiredFields(message); err != nil {
		return fmt.Errorf("required field validation failed: %w", err)
	}

	// Validate message type
	if err := v.validateMessageType(message); err != nil {
		return fmt.Errorf("message type validation failed: %w", err)
	}

	// Validate data structure based on message type
	if err := v.validateDataStructure(message); err != nil {
		return fmt.Errorf("data structure validation failed: %w", err)
	}

	// Validate metadata
	if err := v.validateMetadata(message); err != nil {
		return fmt.Errorf("metadata validation failed: %w", err)
	}

	return nil
}

// validateRequiredFields validates that all required fields are present
func (v *MessageValidator) validateRequiredFields(message types.MonitoringMessage) error {
	if message.MessageID == "" {
		return fmt.Errorf("message_id is required")
	}

	if message.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if message.Timestamp == 0 {
		return fmt.Errorf("timestamp is required")
	}

	if message.MessageType == "" {
		return fmt.Errorf("message_type is required")
	}

	if message.Data == nil {
		return fmt.Errorf("data is required")
	}

	if message.Version == "" {
		return fmt.Errorf("version is required")
	}

	return nil
}

// validateMessageType validates the message type is supported
func (v *MessageValidator) validateMessageType(message types.MonitoringMessage) error {
	validTypes := []string{
		types.MessageTypeQueryLogs,
		types.MessageTypeRDSInstances,
		types.MessageTypeRDSConfig,
		types.MessageTypeRDSSnapshots,
		types.MessageTypeCloudTrail,
		types.MessageTypeHealth,
		types.MessageTypeAgentHealth,
		types.MessageTypeConfig,
	}

	for _, validType := range validTypes {
		if message.MessageType == validType {
			return nil
		}
	}

	return fmt.Errorf("invalid message type: %s, must be one of: %s",
		message.MessageType, strings.Join(validTypes, ", "))
}

// validateDataStructure validates the data structure matches the message type
func (v *MessageValidator) validateDataStructure(message types.MonitoringMessage) error {
	switch message.MessageType {
	case types.MessageTypeQueryLogs:
		return v.validateQueryLogData(message.Data)
	case types.MessageTypeRDSInstances:
		return v.validateRDSInstanceData(message.Data)
	case types.MessageTypeRDSConfig:
		return v.validateRDSConfigData(message.Data)
	case types.MessageTypeRDSSnapshots:
		return v.validateRDSSnapshotData(message.Data)
	case types.MessageTypeCloudTrail:
		return v.validateCloudTrailData(message.Data)
	case types.MessageTypeHealth:
		return v.validateHealthData(message.Data)
	case types.MessageTypeAgentHealth:
		return v.validateAgentHealthData(message.Data)
	case types.MessageTypeConfig:
		return v.validateConfigData(message.Data)
	default:
		return fmt.Errorf("unsupported message type for data validation: %s", message.MessageType)
	}
}

// validateQueryLogData validates query log event data
func (v *MessageValidator) validateQueryLogData(data interface{}) error {
	// For now, accept any data structure for query logs
	// In production, this would validate against types.QueryLogEvent
	if data == nil {
		return fmt.Errorf("query log data cannot be nil")
	}
	return nil
}

// validateRDSInstanceData validates RDS instance event data
func (v *MessageValidator) validateRDSInstanceData(data interface{}) error {
	rdsEvent, ok := data.(*types.RDSInstanceEvent)
	if !ok {
		return fmt.Errorf("data must be of type RDSInstanceEvent")
	}

	if rdsEvent.InstanceID == "" {
		return fmt.Errorf("instance_id is required for RDS instance events")
	}

	if rdsEvent.Status == "" {
		return fmt.Errorf("status is required for RDS instance events")
	}

	if rdsEvent.Engine == "" {
		return fmt.Errorf("engine is required for RDS instance events")
	}

	return nil
}

// validateRDSConfigData validates RDS config event data
func (v *MessageValidator) validateRDSConfigData(data interface{}) error {
	// For now, accept any data structure for RDS config
	// In production, this would validate against types.RDSConfigEvent
	if data == nil {
		return fmt.Errorf("RDS config data cannot be nil")
	}
	return nil
}

// validateRDSSnapshotData validates RDS snapshot event data
func (v *MessageValidator) validateRDSSnapshotData(data interface{}) error {
	snapshotEvent, ok := data.(*types.RDSSnapshotEvent)
	if !ok {
		return fmt.Errorf("data must be of type RDSSnapshotEvent")
	}

	if snapshotEvent.SnapshotID == "" {
		return fmt.Errorf("snapshot_id is required for RDS snapshot events")
	}

	if snapshotEvent.InstanceID == "" {
		return fmt.Errorf("instance_id is required for RDS snapshot events")
	}

	if snapshotEvent.Status == "" {
		return fmt.Errorf("status is required for RDS snapshot events")
	}

	return nil
}

// validateCloudTrailData validates CloudTrail event data
func (v *MessageValidator) validateCloudTrailData(data interface{}) error {
	cloudTrailEvent, ok := data.(*types.CloudTrailEvent)
	if !ok {
		return fmt.Errorf("data must be of type CloudTrailEvent")
	}

	if cloudTrailEvent.EventID == "" {
		return fmt.Errorf("event_id is required for CloudTrail events")
	}

	if cloudTrailEvent.EventName == "" {
		return fmt.Errorf("event_name is required for CloudTrail events")
	}

	if cloudTrailEvent.EventSource == "" {
		return fmt.Errorf("event_source is required for CloudTrail events")
	}

	return nil
}

// validateHealthData validates health event data
func (v *MessageValidator) validateHealthData(data interface{}) error {
	healthEvent, ok := data.(*types.HealthEvent)
	if !ok {
		return fmt.Errorf("data must be of type HealthEvent")
	}

	if healthEvent.ComponentName == "" {
		return fmt.Errorf("component_name is required for health events")
	}

	if healthEvent.Status == "" {
		return fmt.Errorf("status is required for health events")
	}

	return nil
}

// validateAgentHealthData validates agent health event data
func (v *MessageValidator) validateAgentHealthData(data interface{}) error {
	healthEvent, ok := data.(*types.AgentHealthEvent)
	if !ok {
		return fmt.Errorf("data must be of type AgentHealthEvent")
	}

	if healthEvent.AgentVersion == "" {
		return fmt.Errorf("agent_version is required for agent health events")
	}

	if healthEvent.Status == "" {
		return fmt.Errorf("status is required for agent health events")
	}

	return nil
}

// validateConfigData validates config event data
func (v *MessageValidator) validateConfigData(data interface{}) error {
	// For now, accept any data structure for config
	// In production, this would validate against types.ConfigEvent
	if data == nil {
		return fmt.Errorf("config data cannot be nil")
	}
	return nil
}

// validateMetadata validates the message metadata
func (v *MessageValidator) validateMetadata(message types.MonitoringMessage) error {
	if message.Metadata == nil {
		// Metadata is optional
		return nil
	}

	// Validate specific metadata fields if present
	if source, exists := message.Metadata["source"]; exists {
		if sourceStr, ok := source.(string); !ok || sourceStr == "" {
			return fmt.Errorf("metadata.source must be a non-empty string")
		}
	}

	if eventID, exists := message.Metadata["event_id"]; exists {
		if eventIDStr, ok := eventID.(string); !ok || eventIDStr == "" {
			return fmt.Errorf("metadata.event_id must be a non-empty string")
		}
	}

	if collector, exists := message.Metadata["collector"]; exists {
		if collectorStr, ok := collector.(string); !ok || collectorStr == "" {
			return fmt.Errorf("metadata.collector must be a non-empty string")
		}
	}

	return nil
}
