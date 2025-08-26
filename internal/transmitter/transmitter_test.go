package transmitter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/internal/hmac"
	"github.com/lattiq/sentinel/pkg/types"
	"github.com/lattiq/sentinel/version"
)

func TestNewHTTPTransmitter(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.WatchtowerConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  createTestTransmissionConfig(),
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "empty endpoint",
			config: &config.WatchtowerConfig{
				Endpoint:    "",
				Timeout:     30 * time.Second,
				Compression: false,
				HMAC: hmac.Config{
					SecretKey:       "test-secret",
					Algorithm:       "sha256",
					HeaderName:      "X-Signature",
					TimestampHeader: "X-Timestamp",
					AuthWindow:      "5m",
				},
			},
			wantErr: false, // Constructor doesn't validate endpoint
		},
		{
			name: "empty secret key",
			config: &config.WatchtowerConfig{
				Endpoint:    "http://test.com",
				Timeout:     30 * time.Second,
				Compression: false,
				HMAC: hmac.Config{
					SecretKey:       "",
					Algorithm:       "sha256",
					HeaderName:      "X-Signature",
					TimestampHeader: "X-Timestamp",
					AuthWindow:      "5m",
				},
			},
			wantErr: false, // Constructor doesn't validate secret key
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transmitter, err := NewHTTPTransmitter(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, transmitter)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, transmitter)
			}
		})
	}
}

func TestHTTPTransmitter_Send(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and headers
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NotEmpty(t, r.Header.Get("X-Signature"))
		assert.NotEmpty(t, r.Header.Get("X-Timestamp"))

		// Verify request body
		var payload types.BatchPayload
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Len(t, payload.Messages, 2)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	}))
	defer server.Close()

	// Create transmitter
	config := createTestTransmissionConfig()
	config.Endpoint = server.URL
	transmitter, err := NewHTTPTransmitter(config)
	require.NoError(t, err)

	// Create test batch
	batch := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
		createTestMonitoringMessage("msg2"),
	}

	// Send batch
	ctx := context.Background()
	err = transmitter.Send(ctx, batch)
	assert.NoError(t, err)

	// Check metrics
	metrics := transmitter.GetMetrics()
	assert.Equal(t, int64(1), metrics.TotalRequests)
	assert.Equal(t, int64(1), metrics.SuccessfulSends)
	assert.Equal(t, int64(0), metrics.FailedSends)
}

func TestHTTPTransmitter_SendWithRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// Fail first two attempts
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "server error"}`))
		} else {
			// Succeed on third attempt
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success"}`))
		}
	}))
	defer server.Close()

	// Create transmitter
	config := createTestTransmissionConfig()
	config.Endpoint = server.URL
	transmitter, err := NewHTTPTransmitter(config)
	require.NoError(t, err)

	// Create test batch
	batch := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
	}

	// Send batch
	ctx := context.Background()
	err = transmitter.Send(ctx, batch)
	assert.NoError(t, err)
	assert.Equal(t, 3, attempts) // Server should be called 3 times

	// Check metrics - resty handles retries internally, so we only count final result
	metrics := transmitter.GetMetrics()
	assert.Equal(t, int64(1), metrics.TotalRequests) // 1 logical request
	assert.Equal(t, int64(1), metrics.SuccessfulSends)
	assert.Equal(t, int64(0), metrics.FailedSends)
	// Note: RetryRequests is not easily tracked with resty's internal retry mechanism
}

func TestHTTPTransmitter_SendFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server error"}`))
	}))
	defer server.Close()

	// Create transmitter
	config := createTestTransmissionConfig()
	config.Endpoint = server.URL
	transmitter, err := NewHTTPTransmitter(config)
	require.NoError(t, err)

	// Create test batch
	batch := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
	}

	// Send batch - should fail after retries
	ctx := context.Background()
	err = transmitter.Send(ctx, batch)
	assert.Error(t, err)

	// Check metrics - resty handles retries internally, so we only count final result
	metrics := transmitter.GetMetrics()
	assert.Equal(t, int64(1), metrics.TotalRequests) // 1 logical request
	assert.Equal(t, int64(0), metrics.SuccessfulSends)
	assert.Equal(t, int64(1), metrics.FailedSends)
}

func TestHTTPTransmitter_SendClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // Client error - should not retry
		w.Write([]byte(`{"error": "bad request"}`))
	}))
	defer server.Close()

	// Create transmitter
	config := createTestTransmissionConfig()
	config.Endpoint = server.URL
	transmitter, err := NewHTTPTransmitter(config)
	require.NoError(t, err)

	// Create test batch
	batch := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
	}

	// Send batch - should fail immediately without retries
	ctx := context.Background()
	err = transmitter.Send(ctx, batch)
	assert.Error(t, err)

	// Check metrics - no retries for client errors
	metrics := transmitter.GetMetrics()
	assert.Equal(t, int64(1), metrics.TotalRequests)
	assert.Equal(t, int64(0), metrics.SuccessfulSends)
	assert.Equal(t, int64(1), metrics.FailedSends)
	assert.Equal(t, int64(0), metrics.RetriedRequests) // No retries for client errors
}

func TestHTTPTransmitter_GenerateSignature(t *testing.T) {
	config := createTestTransmissionConfig()
	transmitter, err := NewHTTPTransmitter(config)
	require.NoError(t, err)

	payload := []byte(`{"test": "data"}`)
	timestamp := time.Now().Unix()

	signature, err := transmitter.hmacAuth.GenerateSignature("POST", "/test", payload, timestamp)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.Len(t, signature, 64) // HMAC-SHA256 should be 64 characters

	// Same input should produce same signature
	signature2, err := transmitter.hmacAuth.GenerateSignature("POST", "/test", payload, timestamp)
	require.NoError(t, err)
	assert.Equal(t, signature, signature2)

	// Different input should produce different signature
	signature3, err := transmitter.hmacAuth.GenerateSignature("POST", "/test", []byte("different"), timestamp)
	require.NoError(t, err)
	assert.NotEqual(t, signature, signature3)
}

func TestHTTPTransmitter_ContextCancellation(t *testing.T) {
	// Create server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	}))
	defer server.Close()

	// Create transmitter
	config := createTestTransmissionConfig()
	config.Endpoint = server.URL
	transmitter, err := NewHTTPTransmitter(config)
	require.NoError(t, err)

	// Create test batch
	batch := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
	}

	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Send batch - should be cancelled
	err = transmitter.Send(ctx, batch)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context")
}

func TestHTTPTransmitter_EmptyBatch(t *testing.T) {
	config := createTestTransmissionConfig()
	transmitter, err := NewHTTPTransmitter(config)
	require.NoError(t, err)

	// Send empty batch
	ctx := context.Background()
	err = transmitter.Send(ctx, []types.MonitoringMessage{})
	assert.NoError(t, err) // Empty batch should be handled gracefully
}

func TestHTTPTransmitter_InvalidEndpoint(t *testing.T) {
	config := createTestTransmissionConfig()
	config.Endpoint = "invalid-url"
	transmitter, err := NewHTTPTransmitter(config)
	require.NoError(t, err)

	// Create test batch
	batch := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
	}

	// Send batch - should fail
	ctx := context.Background()
	err = transmitter.Send(ctx, batch)
	assert.Error(t, err)

	// Check metrics - resty handles retries internally, so we only count final result
	metrics := transmitter.GetMetrics()
	assert.Equal(t, int64(1), metrics.TotalRequests) // 1 logical request
	assert.Equal(t, int64(0), metrics.SuccessfulSends)
	assert.Equal(t, int64(1), metrics.FailedSends)
}

func TestHTTPTransmitter_GetMetrics(t *testing.T) {
	config := createTestTransmissionConfig()
	transmitter, err := NewHTTPTransmitter(config)
	require.NoError(t, err)

	// Initial metrics should be zero
	metrics := transmitter.GetMetrics()
	assert.Equal(t, int64(0), metrics.TotalRequests)
	assert.Equal(t, int64(0), metrics.SuccessfulSends)
	assert.Equal(t, int64(0), metrics.FailedSends)
	assert.Equal(t, int64(0), metrics.RetriedRequests)
	assert.Equal(t, time.Duration(0), metrics.AvgResponseTime)
}

// Helper functions

func createTestTransmissionConfig() *config.WatchtowerConfig {
	return &config.WatchtowerConfig{
		Endpoint:    "http://test.example.com",
		Timeout:     30 * time.Second,
		Compression: false,
		HMAC: hmac.Config{
			SecretKey:       "test-secret-key",
			Algorithm:       "sha256",
			HeaderName:      "X-Signature",
			TimestampHeader: "X-Timestamp",
			AuthWindow:      "5m",
		},
	}
}

func createTestMonitoringMessage(id string) types.MonitoringMessage {
	return types.MonitoringMessage{
		MessageID:   id,
		ClientID:    "test-client",
		Timestamp:   time.Now().Unix(),
		MessageType: types.MessageTypeQueryLogs,
		BatchSize:   1,
		Data:        map[string]interface{}{"test": "data"},
		Metadata: map[string]interface{}{
			"source":    "test-source",
			"event_id":  "test-event",
			"collector": "test-collector",
		},
		Version: version.Version(),
	}
}
