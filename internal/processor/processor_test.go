package processor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/pkg/types"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  createTestConfig(),
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, err := New(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, processor)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, processor)
			}
		})
	}
}

func TestEventProcessor_Process(t *testing.T) {
	processor, err := New(createTestConfig())
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name          string
		events        []types.Event
		expectedCount int
		expectError   bool
	}{
		{
			name:          "empty events",
			events:        []types.Event{},
			expectedCount: 0,
			expectError:   false,
		},
		{
			name: "query log event",
			events: []types.Event{
				createTestQueryLogEvent(),
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "rds instance event",
			events: []types.Event{
				createTestRDSInstanceEvent(),
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "rds snapshot event",
			events: []types.Event{
				createTestRDSSnapshotEvent(),
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "cloudtrail event",
			events: []types.Event{
				createTestCloudTrailEvent(),
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "agent health event",
			events: []types.Event{
				createTestAgentHealthEvent(),
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "rds config event",
			events: []types.Event{
				createTestRDSConfigEvent(),
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "health event",
			events: []types.Event{
				createTestHealthEvent(),
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "multiple events",
			events: []types.Event{
				createTestQueryLogEvent(),
				createTestRDSInstanceEvent(),
				createTestRDSSnapshotEvent(),
			},
			expectedCount: 3,
			expectError:   false,
		},
		{
			name: "unsupported event type",
			events: []types.Event{
				{
					ID:        "test-unsupported",
					Type:      "unsupported",
					Timestamp: time.Now(),
					Source:    "test",
				},
			},
			expectedCount: 0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messages, err := processor.Process(ctx, tt.events)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, messages, tt.expectedCount)

				// Validate message structure
				for _, msg := range messages {
					assert.NotEmpty(t, msg.MessageID)
					assert.Equal(t, "test-client", msg.ClientID)
					assert.NotZero(t, msg.Timestamp)
					assert.NotEmpty(t, msg.MessageType)
					assert.Equal(t, 1, msg.BatchSize)
					assert.NotNil(t, msg.Data)
					assert.Equal(t, "1.0", msg.Version)
					assert.NotNil(t, msg.Metadata)
				}
			}
		})
	}
}

func TestEventProcessor_ProcessQueryLogEvent(t *testing.T) {
	processor, err := New(createTestConfig())
	require.NoError(t, err)

	ctx := context.Background()
	event := createTestQueryLogEvent()

	messages, err := processor.Process(ctx, []types.Event{event})
	require.NoError(t, err)
	require.Len(t, messages, 1)

	msg := messages[0]
	assert.Equal(t, types.MessageTypeQueryLogs, msg.MessageType)
	assert.Equal(t, "query_logs", msg.Metadata["collector"])
	assert.Equal(t, event.ID, msg.Metadata["event_id"])
	assert.Equal(t, event.Source, msg.Metadata["source"])
}

func TestEventProcessor_ProcessRDSInstanceEvent(t *testing.T) {
	processor, err := New(createTestConfig())
	require.NoError(t, err)

	ctx := context.Background()
	event := createTestRDSInstanceEvent()

	messages, err := processor.Process(ctx, []types.Event{event})
	require.NoError(t, err)
	require.Len(t, messages, 1)

	msg := messages[0]
	assert.Equal(t, types.MessageTypeRDSInstances, msg.MessageType)
	assert.Equal(t, "rds_instances", msg.Metadata["collector"])
	assert.Equal(t, "test-instance", msg.Metadata["instance_id"])

	// Verify data structure
	rdsData, ok := msg.Data.(*types.RDSInstanceEvent)
	require.True(t, ok)
	assert.Equal(t, "test-instance", rdsData.InstanceID)
	assert.Equal(t, "available", rdsData.Status)
}

func TestEventProcessor_ProcessRDSSnapshotEvent(t *testing.T) {
	processor, err := New(createTestConfig())
	require.NoError(t, err)

	ctx := context.Background()
	event := createTestRDSSnapshotEvent()

	messages, err := processor.Process(ctx, []types.Event{event})
	require.NoError(t, err)
	require.Len(t, messages, 1)

	msg := messages[0]
	assert.Equal(t, types.MessageTypeRDSSnapshots, msg.MessageType)
	assert.Equal(t, "rds_snapshots", msg.Metadata["collector"])
	assert.Equal(t, "test-snapshot", msg.Metadata["snapshot_id"])
	assert.Equal(t, "test-instance", msg.Metadata["instance_id"])
}

func TestEventProcessor_ProcessCloudTrailEvent(t *testing.T) {
	processor, err := New(createTestConfig())
	require.NoError(t, err)

	ctx := context.Background()
	event := createTestCloudTrailEvent()

	messages, err := processor.Process(ctx, []types.Event{event})
	require.NoError(t, err)
	require.Len(t, messages, 1)

	msg := messages[0]
	assert.Equal(t, types.MessageTypeCloudTrail, msg.MessageType)
	assert.Equal(t, "cloudtrail", msg.Metadata["collector"])
	assert.Equal(t, "CreateDBSnapshot", msg.Metadata["event_name"])

	// Verify data structure
	cloudTrailData, ok := msg.Data.(*types.CloudTrailEvent)
	require.True(t, ok)
	assert.Equal(t, "test-event-id", cloudTrailData.EventID)
	assert.Equal(t, "CreateDBSnapshot", cloudTrailData.EventName)
}

func TestEventProcessor_ProcessAgentHealthEvent(t *testing.T) {
	processor, err := New(createTestConfig())
	require.NoError(t, err)

	ctx := context.Background()
	event := createTestAgentHealthEvent()

	messages, err := processor.Process(ctx, []types.Event{event})
	require.NoError(t, err)
	require.Len(t, messages, 1)

	msg := messages[0]
	assert.Equal(t, types.MessageTypeAgentHealth, msg.MessageType)
	assert.Equal(t, "agent_health", msg.Metadata["collector"])
	assert.Equal(t, "1.0.0", msg.Metadata["agent_version"])
	assert.Equal(t, "healthy", msg.Metadata["status"])

	// Verify data structure
	healthData, ok := msg.Data.(*types.AgentHealthEvent)
	require.True(t, ok)
	assert.Equal(t, "1.0.0", healthData.AgentVersion)
	assert.Equal(t, "healthy", healthData.Status)
	assert.Equal(t, int64(3600), healthData.UptimeSeconds)
	assert.Equal(t, int64(0), healthData.ErrorCount)
}

func TestEventProcessor_GenerateMessageID(t *testing.T) {
	processor, err := New(createTestConfig())
	require.NoError(t, err)

	event1 := createTestQueryLogEvent()
	event2 := createTestQueryLogEvent()
	event2.ID = "different-id"

	id1 := processor.generateMessageID(event1)
	id2 := processor.generateMessageID(event2)

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2) // Different events should have different IDs
	assert.Len(t, id1, 32)       // MD5 hash should be 32 characters
}

func TestEventProcessor_GetMetrics(t *testing.T) {
	processor, err := New(createTestConfig())
	require.NoError(t, err)

	// Process some events to generate metrics
	ctx := context.Background()
	events := []types.Event{
		createTestQueryLogEvent(),
		createTestRDSInstanceEvent(),
	}

	_, err = processor.Process(ctx, events)
	require.NoError(t, err)

	metrics := processor.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Contains(t, metrics, "processed_events")
	assert.Contains(t, metrics, "error_count")
	assert.Contains(t, metrics, "last_process_time")

	assert.Equal(t, int64(2), metrics["processed_events"])
	assert.Equal(t, int64(0), metrics["error_count"])
}

func TestEventProcessor_ErrorHandling(t *testing.T) {
	processor, err := New(createTestConfig())
	require.NoError(t, err)

	ctx := context.Background()

	// Test event with missing data
	invalidEvent := types.Event{
		ID:        "test-invalid",
		Type:      types.EventTypeQueryLog,
		Timestamp: time.Now(),
		Source:    "test",
		QueryLog:  nil, // Missing data
	}

	messages, err := processor.Process(ctx, []types.Event{invalidEvent})
	assert.Error(t, err)
	assert.Empty(t, messages)

	// Check error metrics
	metrics := processor.GetMetrics()
	assert.Equal(t, int64(1), metrics["error_count"])
}

// Helper functions

func createTestConfig() *config.Config {
	return &config.Config{
		Client: config.ClientConfig{
			ID:          "test-client",
			Environment: "test",
		},
		Batch: config.BatchConfig{
			MaxSize: 100,
			MaxAge:  30 * time.Second,
		},
	}
}

func createTestQueryLogEvent() types.Event {
	return types.Event{
		ID:        "test-query-log",
		Type:      types.EventTypeQueryLog,
		Timestamp: time.Now(),
		Source:    "test-source",
		QueryLog: &types.QueryLogEvent{
			Timestamp:    time.Now().Unix(),
			DatabaseName: "test_db",
			UserName:     "test_user",
			QueryHash:    "abc123",
			QueryPattern: "SELECT * FROM test",
			Duration:     100,
			QueryType:    "SELECT",
		},
	}
}

func createTestRDSInstanceEvent() types.Event {
	return types.Event{
		ID:        "test-rds-instance",
		Type:      types.EventTypeRDSInstance,
		Timestamp: time.Now(),
		Source:    "test-source",
		RDSInstance: &types.RDSInstanceEvent{
			InstanceID:            "test-instance",
			Status:                "available",
			Engine:                "postgres",
			EngineVersion:         "13.7",
			InstanceClass:         "db.t3.micro",
			LastModified:          time.Now().Unix(),
			BackupRetentionPeriod: 7,
			MultiAZ:               false,
			AllocatedStorage:      20,
			StorageType:           "gp2",
			StorageEncrypted:      true,
			PubliclyAccessible:    false,
		},
	}
}

func createTestRDSSnapshotEvent() types.Event {
	return types.Event{
		ID:        "test-rds-snapshot",
		Type:      types.EventTypeRDSSnapshot,
		Timestamp: time.Now(),
		Source:    "test-source",
		RDSSnapshot: &types.RDSSnapshotEvent{
			SnapshotID:       "test-snapshot",
			InstanceID:       "test-instance",
			SnapshotType:     "manual",
			CreateTime:       time.Now().Unix(),
			Status:           "available",
			AllocatedStorage: 20,
			Encrypted:        true,
			Engine:           "postgres",
			EngineVersion:    "13.7",
		},
	}
}

func createTestCloudTrailEvent() types.Event {
	return types.Event{
		ID:        "test-cloudtrail",
		Type:      types.EventTypeCloudTrail,
		Timestamp: time.Now(),
		Source:    "test-source",
		CloudTrail: &types.CloudTrailEvent{
			EventID:     "test-event-id",
			EventName:   "CreateDBSnapshot",
			EventTime:   time.Now().Unix(),
			EventSource: "rds.amazonaws.com",
			AWSRegion:   "us-east-1",
			SourceIP:    "192.168.1.1",
			UserIdentity: types.UserIdentity{
				Type:        "IAMUser",
				PrincipalId: "AIDACKCEVSQ6C2EXAMPLE",
				UserName:    "test-user",
			},
		},
	}
}

func createTestAgentHealthEvent() types.Event {
	return types.Event{
		ID:        "test-agent-health",
		Type:      types.EventTypeAgentHealth,
		Timestamp: time.Now(),
		Source:    "test-source",
		AgentHealth: &types.AgentHealthEvent{
			AgentVersion:    "1.0.0",
			Status:          "healthy",
			UptimeSeconds:   3600,
			CollectorStates: map[string]string{"query_logs": "running"},
			SystemMetrics: types.SystemMetrics{
				MemoryUsageMB:  256,
				CPUPercent:     15.5,
				DiskUsageMB:    1024,
				GoroutineCount: 42,
			},
			ErrorCount: 0,
			Timestamp:  time.Now().Unix(),
		},
	}
}

func createTestRDSConfigEvent() types.Event {
	return types.Event{
		ID:        "test-rds-config",
		Type:      types.EventTypeRDSConfig,
		Timestamp: time.Now(),
		Source:    "test-source",
		RDSConfig: &types.RDSConfigEvent{
			InstanceID:     "test-instance",
			ParameterGroup: "test-parameter-group",
			Parameters:     []types.ConfigParameter{},
			LastModified:   time.Now().Unix(),
			ApplyMethod:    "immediate",
		},
	}
}

func createTestHealthEvent() types.Event {
	return types.Event{
		ID:        "test-health",
		Type:      types.EventTypeHealth,
		Timestamp: time.Now(),
		Source:    "test-source",
		Health: &types.HealthEvent{
			ComponentName: "test-component",
			Status:        "healthy",
			Timestamp:     time.Now().Unix(),
			UptimeSeconds: 3600,
			ErrorCount:    0,
		},
	}
}
