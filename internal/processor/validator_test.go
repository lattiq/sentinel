package processor

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/lattiq/sentinel/pkg/types"
)

func TestNewMessageValidator(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	validator := NewMessageValidator(logger)

	assert.NotNil(t, validator)
	assert.NotNil(t, validator.logger)
}

func TestMessageValidator_ValidateRequiredFields(t *testing.T) {
	validator := NewMessageValidator(logrus.NewEntry(logrus.New()))

	tests := []struct {
		name    string
		message types.MonitoringMessage
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid message",
			message: createValidMonitoringMessage(),
			wantErr: false,
		},
		{
			name: "missing message_id",
			message: types.MonitoringMessage{
				ClientID:    "test-client",
				Timestamp:   1234567890,
				MessageType: types.MessageTypeQueryLogs,
				Data:        map[string]interface{}{"test": "data"},
				Version:     "1.0",
			},
			wantErr: true,
			errMsg:  "message_id is required",
		},
		{
			name: "missing client_id",
			message: types.MonitoringMessage{
				MessageID:   "test-msg-id",
				Timestamp:   1234567890,
				MessageType: types.MessageTypeQueryLogs,
				Data:        map[string]interface{}{"test": "data"},
				Version:     "1.0",
			},
			wantErr: true,
			errMsg:  "client_id is required",
		},
		{
			name: "missing timestamp",
			message: types.MonitoringMessage{
				MessageID:   "test-msg-id",
				ClientID:    "test-client",
				MessageType: types.MessageTypeQueryLogs,
				Data:        map[string]interface{}{"test": "data"},
				Version:     "1.0",
			},
			wantErr: true,
			errMsg:  "timestamp is required",
		},
		{
			name: "missing message_type",
			message: types.MonitoringMessage{
				MessageID: "test-msg-id",
				ClientID:  "test-client",
				Timestamp: 1234567890,
				Data:      map[string]interface{}{"test": "data"},
				Version:   "1.0",
			},
			wantErr: true,
			errMsg:  "message_type is required",
		},
		{
			name: "missing data",
			message: types.MonitoringMessage{
				MessageID:   "test-msg-id",
				ClientID:    "test-client",
				Timestamp:   1234567890,
				MessageType: types.MessageTypeQueryLogs,
				Version:     "1.0",
			},
			wantErr: true,
			errMsg:  "data is required",
		},
		{
			name: "missing version",
			message: types.MonitoringMessage{
				MessageID:   "test-msg-id",
				ClientID:    "test-client",
				Timestamp:   1234567890,
				MessageType: types.MessageTypeQueryLogs,
				Data:        map[string]interface{}{"test": "data"},
			},
			wantErr: true,
			errMsg:  "version is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.message)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMessageValidator_ValidateMessageType(t *testing.T) {
	validator := NewMessageValidator(logrus.NewEntry(logrus.New()))

	// Test valid message types with proper data structures
	testCases := map[string]interface{}{
		types.MessageTypeQueryLogs: map[string]interface{}{"test": "data"},
		types.MessageTypeRDSInstances: &types.RDSInstanceEvent{
			InstanceID: "test-instance",
			Status:     "available",
			Engine:     "postgres",
		},
		types.MessageTypeRDSConfig: &types.RDSConfigEvent{
			InstanceID:     "test-instance",
			ParameterGroup: "test-parameter-group",
			Parameters:     []types.ConfigParameter{},
			LastModified:   time.Now().Unix(),
			ApplyMethod:    "immediate",
		},
		types.MessageTypeRDSSnapshots: &types.RDSSnapshotEvent{
			SnapshotID: "test-snapshot",
			InstanceID: "test-instance",
			Status:     "available",
		},
		types.MessageTypeCloudTrail: &types.CloudTrailEvent{
			EventID:     "test-event-id",
			EventName:   "CreateDBSnapshot",
			EventSource: "rds.amazonaws.com",
		},
		types.MessageTypeHealth: &types.HealthEvent{
			ComponentName: "test-component",
			Status:        "healthy",
		},
		types.MessageTypeAgentHealth: &types.AgentHealthEvent{
			AgentVersion: "1.0.0",
			Status:       "healthy",
		},
	}

	for msgType, data := range testCases {
		t.Run("valid_type_"+msgType, func(t *testing.T) {
			message := createValidMonitoringMessage()
			message.MessageType = msgType
			message.Data = data
			err := validator.Validate(message)
			assert.NoError(t, err)
		})
	}

	// Test invalid message type
	t.Run("invalid_type", func(t *testing.T) {
		message := createValidMonitoringMessage()
		message.MessageType = "invalid_type"
		err := validator.Validate(message)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid message type")
	})
}

func TestMessageValidator_ValidateRDSInstanceData(t *testing.T) {
	validator := NewMessageValidator(logrus.NewEntry(logrus.New()))

	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid RDS instance data",
			data: &types.RDSInstanceEvent{
				InstanceID: "test-instance",
				Status:     "available",
				Engine:     "postgres",
			},
			wantErr: false,
		},
		{
			name:    "wrong data type",
			data:    map[string]interface{}{"test": "data"},
			wantErr: true,
			errMsg:  "data must be of type RDSInstanceEvent",
		},
		{
			name: "missing instance_id",
			data: &types.RDSInstanceEvent{
				Status: "available",
				Engine: "postgres",
			},
			wantErr: true,
			errMsg:  "instance_id is required",
		},
		{
			name: "missing status",
			data: &types.RDSInstanceEvent{
				InstanceID: "test-instance",
				Engine:     "postgres",
			},
			wantErr: true,
			errMsg:  "status is required",
		},
		{
			name: "missing engine",
			data: &types.RDSInstanceEvent{
				InstanceID: "test-instance",
				Status:     "available",
			},
			wantErr: true,
			errMsg:  "engine is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := createValidMonitoringMessage()
			message.MessageType = types.MessageTypeRDSInstances
			message.Data = tt.data

			err := validator.Validate(message)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMessageValidator_ValidateRDSSnapshotData(t *testing.T) {
	validator := NewMessageValidator(logrus.NewEntry(logrus.New()))

	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid RDS snapshot data",
			data: &types.RDSSnapshotEvent{
				SnapshotID: "test-snapshot",
				InstanceID: "test-instance",
				Status:     "available",
			},
			wantErr: false,
		},
		{
			name:    "wrong data type",
			data:    map[string]interface{}{"test": "data"},
			wantErr: true,
			errMsg:  "data must be of type RDSSnapshotEvent",
		},
		{
			name: "missing snapshot_id",
			data: &types.RDSSnapshotEvent{
				InstanceID: "test-instance",
				Status:     "available",
			},
			wantErr: true,
			errMsg:  "snapshot_id is required",
		},
		{
			name: "missing instance_id",
			data: &types.RDSSnapshotEvent{
				SnapshotID: "test-snapshot",
				Status:     "available",
			},
			wantErr: true,
			errMsg:  "instance_id is required",
		},
		{
			name: "missing status",
			data: &types.RDSSnapshotEvent{
				SnapshotID: "test-snapshot",
				InstanceID: "test-instance",
			},
			wantErr: true,
			errMsg:  "status is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := createValidMonitoringMessage()
			message.MessageType = types.MessageTypeRDSSnapshots
			message.Data = tt.data

			err := validator.Validate(message)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMessageValidator_ValidateCloudTrailData(t *testing.T) {
	validator := NewMessageValidator(logrus.NewEntry(logrus.New()))

	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid CloudTrail data",
			data: &types.CloudTrailEvent{
				EventID:     "test-event-id",
				EventName:   "CreateDBSnapshot",
				EventSource: "rds.amazonaws.com",
			},
			wantErr: false,
		},
		{
			name:    "wrong data type",
			data:    map[string]interface{}{"test": "data"},
			wantErr: true,
			errMsg:  "data must be of type CloudTrailEvent",
		},
		{
			name: "missing event_id",
			data: &types.CloudTrailEvent{
				EventName:   "CreateDBSnapshot",
				EventSource: "rds.amazonaws.com",
			},
			wantErr: true,
			errMsg:  "event_id is required",
		},
		{
			name: "missing event_name",
			data: &types.CloudTrailEvent{
				EventID:     "test-event-id",
				EventSource: "rds.amazonaws.com",
			},
			wantErr: true,
			errMsg:  "event_name is required",
		},
		{
			name: "missing event_source",
			data: &types.CloudTrailEvent{
				EventID:   "test-event-id",
				EventName: "CreateDBSnapshot",
			},
			wantErr: true,
			errMsg:  "event_source is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := createValidMonitoringMessage()
			message.MessageType = types.MessageTypeCloudTrail
			message.Data = tt.data

			err := validator.Validate(message)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMessageValidator_ValidateAgentHealthData(t *testing.T) {
	validator := NewMessageValidator(logrus.NewEntry(logrus.New()))

	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid agent health data",
			data: &types.AgentHealthEvent{
				AgentVersion: "1.0.0",
				Status:       "healthy",
			},
			wantErr: false,
		},
		{
			name:    "wrong data type",
			data:    map[string]interface{}{"test": "data"},
			wantErr: true,
			errMsg:  "data must be of type AgentHealthEvent",
		},
		{
			name: "missing agent_version",
			data: &types.AgentHealthEvent{
				Status: "healthy",
			},
			wantErr: true,
			errMsg:  "agent_version is required",
		},
		{
			name: "missing status",
			data: &types.AgentHealthEvent{
				AgentVersion: "1.0.0",
			},
			wantErr: true,
			errMsg:  "status is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := createValidMonitoringMessage()
			message.MessageType = types.MessageTypeAgentHealth
			message.Data = tt.data

			err := validator.Validate(message)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMessageValidator_ValidateMetadata(t *testing.T) {
	validator := NewMessageValidator(logrus.NewEntry(logrus.New()))

	tests := []struct {
		name     string
		metadata map[string]interface{}
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			wantErr:  false,
		},
		{
			name: "valid metadata",
			metadata: map[string]interface{}{
				"source":      "test-source",
				"event_id":    "test-event",
				"collector":   "test-collector",
				"environment": "test",
			},
			wantErr: false,
		},
		{
			name: "invalid source type",
			metadata: map[string]interface{}{
				"source": 123,
			},
			wantErr: true,
			errMsg:  "metadata.source must be a non-empty string",
		},
		{
			name: "empty source",
			metadata: map[string]interface{}{
				"source": "",
			},
			wantErr: true,
			errMsg:  "metadata.source must be a non-empty string",
		},
		{
			name: "invalid event_id type",
			metadata: map[string]interface{}{
				"event_id": 123,
			},
			wantErr: true,
			errMsg:  "metadata.event_id must be a non-empty string",
		},
		{
			name: "invalid collector type",
			metadata: map[string]interface{}{
				"collector": 123,
			},
			wantErr: true,
			errMsg:  "metadata.collector must be a non-empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := createValidMonitoringMessage()
			message.Metadata = tt.metadata

			err := validator.Validate(message)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMessageValidator_ValidateQueryLogData(t *testing.T) {
	validator := NewMessageValidator(logrus.NewEntry(logrus.New()))

	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid query log data",
			data:    map[string]interface{}{"test": "data"},
			wantErr: false,
		},
		{
			name:    "nil data",
			data:    nil,
			wantErr: true,
			errMsg:  "data is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := createValidMonitoringMessage()
			message.MessageType = types.MessageTypeQueryLogs
			message.Data = tt.data

			err := validator.Validate(message)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function
func createValidMonitoringMessage() types.MonitoringMessage {
	return types.MonitoringMessage{
		MessageID:   "test-msg-id",
		ClientID:    "test-client",
		Timestamp:   1234567890,
		MessageType: types.MessageTypeQueryLogs,
		BatchSize:   1,
		Data:        map[string]interface{}{"test": "data"},
		Metadata: map[string]interface{}{
			"source":    "test-source",
			"event_id":  "test-event",
			"collector": "test-collector",
		},
		Version: "1.0",
	}
}
