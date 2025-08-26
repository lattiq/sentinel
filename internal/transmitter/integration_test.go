package transmitter

import (
	"context"
	"testing"
	"time"

	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/internal/hmac"
	"github.com/lattiq/sentinel/pkg/types"
	"github.com/lattiq/sentinel/version"
	"github.com/stretchr/testify/assert"
)

func TestHTTPTransmitterIntegration(t *testing.T) {
	// Skip if no test server is running
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create test configuration
	testConfig := &config.WatchtowerConfig{
		Endpoint:    "http://localhost:8081",
		Timeout:     30 * time.Second,
		Compression: true,
		ClientID:    "sen-sentinel-client-245db92b",
		HMAC: hmac.Config{
			SecretKey:       "81ad4c2263c2787fa609b47a5203693f6db1edb95c1ba26804018428e19a1209",
			Algorithm:       "sha256",
			HeaderName:      "X-Signature",
			TimestampHeader: "X-Timestamp",
			AuthWindow:      "300s",
		},
	}

	// Create transmitter
	transmitter, err := NewHTTPTransmitter(testConfig)
	assert.NoError(t, err)
	assert.NotNil(t, transmitter)

	// Create test messages
	testMessage := types.MonitoringMessage{
		MessageID:   "test-integration-123",
		ClientID:    "sen-sentinel-client-245db92b",
		Timestamp:   time.Now().Unix(),
		MessageType: types.MessageTypeQueryLogs,
		BatchSize:   1,
		Data: types.QueryLogEvent{
			Timestamp:    time.Now().Unix(),
			DatabaseName: "test_db",
			UserName:     "test_user",
			QueryHash:    "integration-test-abc123",
			QueryPattern: "SELECT * FROM users WHERE id = ?",
			RawQuery:     "SELECT * FROM users WHERE id = 1",
			Duration:     150.5,
			QueryType:    "SELECT",
		},
		Version: version.Version(),
	}

	messages := []types.MonitoringMessage{testMessage}

	// Test sending (will fail if no server, but shouldn't crash)
	ctx := context.Background()
	err = transmitter.Send(ctx, messages)

	// We expect this to fail since there's likely no server running
	// The test is mainly to ensure the code doesn't panic
	if err != nil {
		t.Logf("Expected error when no server running: %v", err)
	}

	// Test metrics
	metrics := transmitter.GetMetrics()
	assert.Equal(t, int64(1), metrics.TotalRequests)

	if err != nil {
		assert.Equal(t, int64(1), metrics.FailedSends)
		assert.Equal(t, int64(0), metrics.SuccessfulSends)
	} else {
		assert.Equal(t, int64(0), metrics.FailedSends)
		assert.Equal(t, int64(1), metrics.SuccessfulSends)
	}
}
