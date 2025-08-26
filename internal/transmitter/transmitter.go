package transmitter

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"

	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/internal/hmac"
	"github.com/lattiq/sentinel/pkg/types"
	"github.com/lattiq/sentinel/version"
)

// HTTPTransmitter handles secure transmission of monitoring messages using resty
type HTTPTransmitter struct {
	config   *config.WatchtowerConfig
	client   *resty.Client
	logger   *logrus.Entry
	hmacAuth *hmac.Authenticator

	// Retry configuration
	retryConfig *RetryConfig

	// Metrics - integrated directly for simplicity
	mu               sync.RWMutex
	totalRequests    int64
	successfulSends  int64
	failedSends      int64
	retriedRequests  int64
	lastTransmitTime time.Time
	avgResponseTime  time.Duration
}

// RetryConfig defines retry behavior
type RetryConfig struct {
	MaxRetries      int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	BackoffFactor   float64
	RetryableErrors []int // HTTP status codes that should be retried
}

// NewHTTPTransmitter creates a new HTTP transmitter using resty
func NewHTTPTransmitter(config *config.WatchtowerConfig) (*HTTPTransmitter, error) {
	if config == nil {
		return nil, fmt.Errorf("transmission configuration is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component": "http_transmitter",
		"endpoint":  config.Endpoint,
	})

	// Create resty client with timeout and retry configuration
	client := resty.New().
		SetTimeout(config.Timeout).
		SetRetryCount(3).
		SetRetryWaitTime(time.Second).
		SetRetryMaxWaitTime(30 * time.Second).
		AddRetryCondition(func(r *resty.Response, err error) bool {
			// Retry on network errors
			if err != nil {
				return true
			}
			// Retry on server errors and rate limiting
			statusCode := r.StatusCode()
			return statusCode >= 500 || statusCode == 429
		})

	// Default retry configuration
	retryConfig := &RetryConfig{
		MaxRetries:      3,
		InitialDelay:    time.Second,
		MaxDelay:        30 * time.Second,
		BackoffFactor:   2.0,
		RetryableErrors: []int{500, 502, 503, 504, 429}, // Server errors and rate limiting
	}

	// Create HMAC authenticator
	hmacAuth := hmac.NewHMACAuthenticator(&config.HMAC)

	transmitter := &HTTPTransmitter{
		config:      config,
		client:      client,
		logger:      logger,
		hmacAuth:    hmacAuth,
		retryConfig: retryConfig,
	}

	logger.Info("HTTP transmitter created with resty")
	return transmitter, nil
}

// Send transmits a batch of monitoring messages
func (t *HTTPTransmitter) Send(ctx context.Context, messages []types.MonitoringMessage) error {
	if len(messages) == 0 {
		return nil
	}

	t.logger.WithField("message_count", len(messages)).Debug("Sending messages")
	startTime := time.Now()

	// Record request attempt
	t.recordRequest()

	// Create batch payload
	batchPayload := types.BatchPayload{
		ClientID:  messages[0].ClientID, // All messages should have same client ID
		Timestamp: time.Now().Unix(),
		BatchSize: len(messages),
		Messages:  messages,
		Metadata: map[string]interface{}{
			"transmission_time": time.Now().Unix(),
			"batch_count":       len(messages),
		},
	}

	// Serialize payload
	payload, err := json.Marshal(batchPayload)
	if err != nil {
		t.recordFailure()
		return fmt.Errorf("failed to marshal batch payload: %w", err)
	}

	// Send request with uncompressed payload for HMAC signature calculation
	// Compression will be handled by resty if Content-Encoding header is set
	err = t.sendRequest(ctx, payload)

	responseTime := time.Since(startTime)

	// Record success or failure
	if err != nil {
		t.recordFailure()
		t.logger.WithError(err).Error("Failed to send messages")
		return fmt.Errorf("failed to send request: %w", err)
	}

	t.recordSuccess(responseTime)
	t.logger.WithFields(logrus.Fields{
		"message_count": len(messages),
		"response_time": responseTime,
	}).Debug("Successfully sent messages")

	return nil
}

// sendRequest sends a single HTTP request using resty
func (t *HTTPTransmitter) sendRequest(ctx context.Context, payload []byte) error {
	// Generate HMAC signature on the uncompressed payload
	timestamp := time.Now().Unix()

	// Use the correct path from the endpoint URL
	apiPath := "/watchtower/v1/events/batch"
	if t.config.Endpoint != "" {
		relativePathFromEndpoint, err := extractPath(t.config.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to extract path from endpoint: %w", err)
		}
		apiPath = path.Join(relativePathFromEndpoint, apiPath)
	}

	signature, err := t.hmacAuth.GenerateSignature("POST", apiPath, payload, timestamp)
	if err != nil {
		return fmt.Errorf("failed to generate HMAC signature: %w", err)
	}

	// Compress payload after signature calculation if configured
	requestPayload := payload
	if t.config.Compression {
		compressedPayload, err := t.compressPayload(payload)
		if err != nil {
			return fmt.Errorf("failed to compress payload: %w", err)
		}
		requestPayload = compressedPayload
	}

	// Prepare request
	request := t.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("User-Agent", fmt.Sprintf("lattiq-sentinel/%s", version.Version())).
		SetHeader(t.config.HMAC.HeaderName, signature).
		SetHeader(t.config.HMAC.TimestampHeader, strconv.FormatInt(timestamp, 10)).
		SetBody(requestPayload)

	// Set compression header if payload was compressed
	if t.config.Compression {
		request.SetHeader("Content-Encoding", "gzip")
	}

	// Add client ID header
	if t.config.ClientID != "" {
		request.SetHeader("X-Client-ID", t.config.ClientID)
	}

	// Send request
	resp, err := request.Post(t.config.Endpoint + apiPath)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}

	// Check response status
	if !resp.IsSuccess() {
		return &HTTPError{
			StatusCode: resp.StatusCode(),
			Message:    string(resp.Body()),
		}
	}

	t.logger.WithField("status_code", resp.StatusCode()).Debug("Request successful")
	return nil
}

// compressPayload compresses the payload using gzip
func (t *HTTPTransmitter) compressPayload(payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)

	_, err := gzWriter.Write(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to write to gzip writer: %w", err)
	}

	err = gzWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return buf.Bytes(), nil
}

// Metrics methods
func (t *HTTPTransmitter) recordRequest() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.totalRequests++
}

func (t *HTTPTransmitter) recordSuccess(responseTime time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.successfulSends++
	t.lastTransmitTime = time.Now()

	// Update average response time (simple moving average)
	if t.avgResponseTime == 0 {
		t.avgResponseTime = responseTime
	} else {
		t.avgResponseTime = (t.avgResponseTime + responseTime) / 2
	}
}

func (t *HTTPTransmitter) recordFailure() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failedSends++
}

func (t *HTTPTransmitter) recordRetry() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.retriedRequests++
}

// GetMetrics returns transmission metrics
func (t *HTTPTransmitter) GetMetrics() types.TransmissionMetrics {
	t.mu.RLock()
	defer t.mu.RUnlock()

	successRate := 0.0
	if t.totalRequests > 0 {
		successRate = float64(t.successfulSends) / float64(t.totalRequests)
	}

	return types.TransmissionMetrics{
		TotalRequests:    t.totalRequests,
		SuccessfulSends:  t.successfulSends,
		FailedSends:      t.failedSends,
		RetriedRequests:  t.retriedRequests,
		SuccessRate:      successRate,
		AvgResponseTime:  t.avgResponseTime,
		LastTransmitTime: t.lastTransmitTime,
	}
}

// HTTPError represents an HTTP error response
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

func extractPath(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	return u.Path, nil
}
