package cloudtrail

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsClient "github.com/lattiq/sentinel/internal/aws"
	"github.com/lattiq/sentinel/internal/config"
	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

func TestCollector_shouldProcessEvent(t *testing.T) {
	tests := []struct {
		name        string
		eventNames  []string
		eventName   string
		shouldMatch bool
	}{
		{
			name:        "empty config should process all events",
			eventNames:  []string{},
			eventName:   "CreateDBSnapshot",
			shouldMatch: true,
		},
		{
			name:        "configured event should match",
			eventNames:  []string{"CreateDBSnapshot", "ModifyDBInstance"},
			eventName:   "CreateDBSnapshot",
			shouldMatch: true,
		},
		{
			name:        "non-configured event should not match",
			eventNames:  []string{"CreateDBSnapshot", "ModifyDBInstance"},
			eventName:   "DescribeDBInstances",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CloudTrailConfig{
				EventNames: tt.eventNames,
			}

			collector := &Collector{config: cfg}
			result := collector.shouldProcessEvent(tt.eventName)
			assert.Equal(t, tt.shouldMatch, result)
		})
	}
}

func TestCollector_extractResourceName(t *testing.T) {
	collector := &Collector{}

	tests := []struct {
		name           string
		requestParams  map[string]interface{}
		eventName      string
		expectedResult string
	}{
		{
			name: "extract dBInstanceIdentifier",
			requestParams: map[string]interface{}{
				"dBInstanceIdentifier": "my-database",
				"otherParam":           "value",
			},
			eventName:      "CreateDBSnapshot",
			expectedResult: "my-database",
		},
		{
			name: "extract dBSnapshotIdentifier",
			requestParams: map[string]interface{}{
				"dBSnapshotIdentifier": "my-snapshot",
				"dBInstanceIdentifier": "my-database",
			},
			eventName:      "CreateDBSnapshot",
			expectedResult: "my-snapshot",
		},
		{
			name: "extract dBClusterIdentifier",
			requestParams: map[string]interface{}{
				"dBClusterIdentifier": "my-aurora-cluster",
				"dBInstanceIdentifier": "my-database",
			},
			eventName:      "CreateDBCluster",
			expectedResult: "my-aurora-cluster",
		},
		{
			name: "extract dBClusterSnapshotIdentifier",
			requestParams: map[string]interface{}{
				"dBClusterSnapshotIdentifier": "my-cluster-snapshot",
				"dBClusterIdentifier":         "my-aurora-cluster",
			},
			eventName:      "CreateDBClusterSnapshot",
			expectedResult: "my-cluster-snapshot",
		},
		{
			name: "extract globalClusterIdentifier",
			requestParams: map[string]interface{}{
				"globalClusterIdentifier": "my-global-cluster",
			},
			eventName:      "CreateGlobalCluster",
			expectedResult: "my-global-cluster",
		},
		{
			name:           "no resource identifiers",
			requestParams:  map[string]interface{}{"otherParam": "value"},
			eventName:      "CreateDBSnapshot",
			expectedResult: "CreateDBSnapshot",
		},
		{
			name:           "nil request params",
			requestParams:  nil,
			eventName:      "CreateDBSnapshot",
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := collector.extractResourceName(tt.requestParams, tt.eventName)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestCollector_convertCloudTrailRecord(t *testing.T) {
	collector := &Collector{}

	now := time.Now()
	record := CloudTrailRecord{
		EventID:         "test-event-id",
		EventName:       "CreateDBSnapshot",
		EventTime:       now,
		EventSource:     "rds.amazonaws.com",
		EventVersion:    "1.08",
		AWSRegion:       "us-east-1",
		SourceIPAddress: "192.168.1.1",
		UserAgent:       "aws-cli/2.0.0",
		RequestParameters: map[string]interface{}{
			"dBSnapshotIdentifier": "test-snapshot",
			"dBInstanceIdentifier": "test-instance",
		},
		ResponseElements: map[string]interface{}{
			"dBSnapshot": map[string]interface{}{
				"status": "creating",
			},
		},
		ReadOnly: false,
		UserIdentity: CloudTrailUserIdentity{
			Type:        "IAMUser",
			PrincipalId: "AIDACKCEVSQ6C2EXAMPLE",
			UserName:    "test-user",
			ARN:         "arn:aws:iam::123456789012:user/test-user",
			AccountId:   "123456789012",
		},
	}

	event := collector.convertCloudTrailRecord(record, "test-object-key")

	assert.Equal(t, record.EventID, event.ID)
	assert.Equal(t, sentinelTypes.EventTypeCloudTrail, event.Type)
	assert.Equal(t, record.EventTime, event.Timestamp)
	assert.Equal(t, "cloudtrail_collector", event.Source)

	require.NotNil(t, event.CloudTrail)
	assert.Equal(t, record.EventID, event.CloudTrail.EventID)
	assert.Equal(t, record.EventName, event.CloudTrail.EventName)
	assert.Equal(t, record.EventTime.Unix(), event.CloudTrail.EventTime)
	assert.Equal(t, record.EventSource, event.CloudTrail.EventSource)
	assert.Equal(t, "test-snapshot", event.CloudTrail.ResourceName)

	assert.Equal(t, record.UserIdentity.Type, event.CloudTrail.UserIdentity.Type)
	assert.Equal(t, record.UserIdentity.UserName, event.CloudTrail.UserIdentity.UserName)
}

func TestNewCollector(t *testing.T) {
	cfg := &config.CloudTrailConfig{
		Enabled:      true,
		S3Bucket:     "test-bucket",
		S3Prefix:     "test-prefix",
		EventNames:   []string{"CreateDBSnapshot"},
		PollInterval: 5 * time.Minute,
		LookbackTime: 15 * time.Minute,
	}

	awsManager := &awsClient.ClientManager{}

	collector, err := NewCollector(cfg, awsManager)
	require.NoError(t, err)
	require.NotNil(t, collector)

	assert.Equal(t, cfg, collector.config)
	assert.Equal(t, awsManager, collector.awsManager)
	assert.Equal(t, "cloudtrail", collector.Name())
}

func TestCollector_EventFiltering(t *testing.T) {
	// Test the filtering logic with different event configurations
	testCases := []struct {
		name             string
		configuredEvents []string
		testEvents       []string
		expectedFiltered []string
	}{
		{
			name:             "RDS events only",
			configuredEvents: []string{"CreateDBSnapshot", "RestoreDBInstanceFromDBSnapshot", "ModifyDBInstance"},
			testEvents:       []string{"CreateDBSnapshot", "DescribeDBInstances", "ModifyDBInstance", "CreateTable"},
			expectedFiltered: []string{"CreateDBSnapshot", "ModifyDBInstance"},
		},
		{
			name:             "Empty configuration processes all",
			configuredEvents: []string{},
			testEvents:       []string{"CreateDBSnapshot", "DescribeDBInstances", "ModifyDBInstance"},
			expectedFiltered: []string{"CreateDBSnapshot", "DescribeDBInstances", "ModifyDBInstance"},
		},
		{
			name:             "No matching events",
			configuredEvents: []string{"CreateDBSnapshot"},
			testEvents:       []string{"DescribeDBInstances", "ListTables"},
			expectedFiltered: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.CloudTrailConfig{
				EventNames: tc.configuredEvents,
			}
			collector := &Collector{config: cfg}

			var filteredEvents []string
			for _, eventName := range tc.testEvents {
				if collector.shouldProcessEvent(eventName) {
					filteredEvents = append(filteredEvents, eventName)
				}
			}

			assert.Equal(t, tc.expectedFiltered, filteredEvents)
		})
	}
}
