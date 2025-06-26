package transmitter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/pkg/types"
)

// HTTPTransmitter handles secure transmission of monitoring messages
type HTTPTransmitter struct {
	config     *config.HubConfig
	httpClient *http.Client
	logger     *logrus.Entry

	// Retry mechanism
	retryConfig *RetryConfig

	// Metrics
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

// NewHTTPTransmitter creates a new HTTP transmitter
func NewHTTPTransmitter(config *config.HubConfig) (*HTTPTransmitter, error) {
	if config == nil {
		return nil, fmt.Errorf("transmission configuration is required")
	}

	logger := logrus.WithFields(logrus.Fields{
		"component": "http_transmitter",
		"endpoint":  config.Endpoint,
	})

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	// Default retry configuration
	retryConfig := &RetryConfig{
		MaxRetries:      3,
		InitialDelay:    time.Second,
		MaxDelay:        30 * time.Second,
		BackoffFactor:   2.0,
		RetryableErrors: []int{500, 502, 503, 504, 429}, // Server errors and rate limiting
	}

	transmitter := &HTTPTransmitter{
		config:      config,
		httpClient:  httpClient,
		logger:      logger,
		retryConfig: retryConfig,
	}

	logger.Info("HTTP transmitter created")
	return transmitter, nil
}

// Send transmits a batch of monitoring messages
func (t *HTTPTransmitter) Send(ctx context.Context, messages []types.MonitoringMessage) error {
	if len(messages) == 0 {
		return nil
	}

	t.logger.WithField("message_count", len(messages)).Debug("Sending messages")
	startTime := time.Now()

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
		return fmt.Errorf("failed to marshal batch payload: %w", err)
	}

	// Compress payload if configured
	if t.config.Compression {
		payload, err = t.compressPayload(payload)
		if err != nil {
			return fmt.Errorf("failed to compress payload: %w", err)
		}
	}

	// Send with retry logic
	err = t.sendWithRetry(ctx, payload)

	// Update metrics
	t.updateMetrics(startTime, err == nil)

	return err
}

// sendWithRetry sends the payload with exponential backoff retry
func (t *HTTPTransmitter) sendWithRetry(ctx context.Context, payload []byte) error {
	var lastErr error
	delay := t.retryConfig.InitialDelay

	for attempt := 0; attempt <= t.retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			t.logger.WithFields(logrus.Fields{
				"attempt": attempt,
				"delay":   delay,
			}).Debug("Retrying transmission")

			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}

			t.retriedRequests++
		}

		err := t.sendRequest(ctx, payload)
		if err == nil {
			if attempt > 0 {
				t.logger.WithField("attempts", attempt+1).Info("Transmission succeeded after retries")
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !t.shouldRetry(err) {
			t.logger.WithError(err).Warn("Non-retryable error, not retrying")
			break
		}

		// Calculate next delay with exponential backoff
		delay = time.Duration(float64(delay) * t.retryConfig.BackoffFactor)
		if delay > t.retryConfig.MaxDelay {
			delay = t.retryConfig.MaxDelay
		}
	}

	return fmt.Errorf("transmission failed after %d attempts: %w", t.retryConfig.MaxRetries+1, lastErr)
}

// sendRequest sends a single HTTP request
func (t *HTTPTransmitter) sendRequest(ctx context.Context, payload []byte) error {
	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", t.config.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "lattiq-sentinel/1.0")

	if t.config.Compression {
		req.Header.Set("Content-Encoding", "gzip")
	}

	// Generate HMAC signature
	signature, err := t.generateHMACSignature(payload)
	if err != nil {
		return fmt.Errorf("failed to generate HMAC signature: %w", err)
	}
	req.Header.Set("X-Signature", signature)

	// Add timestamp header
	req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))

	// Add client ID header
	if t.config.ClientID != "" {
		req.Header.Set("X-Client-ID", t.config.ClientID)
	}

	// Send request
	t.totalRequests++
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}

	t.logger.WithField("status_code", resp.StatusCode).Debug("Request successful")
	return nil
}

// generateHMACSignature generates HMAC-SHA256 signature for the payload
func (t *HTTPTransmitter) generateHMACSignature(payload []byte) (string, error) {
	if t.config.SecretKey == "" {
		return "", fmt.Errorf("secret key is required for HMAC signature")
	}

	mac := hmac.New(sha256.New, []byte(t.config.SecretKey))
	mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))

	return signature, nil
}

// compressPayload compresses the payload using gzip
func (t *HTTPTransmitter) compressPayload(payload []byte) ([]byte, error) {
	// For now, return as-is. In production, implement gzip compression
	// This would use gzip.Writer to compress the payload
	return payload, nil
}

// shouldRetry determines if an error should trigger a retry
func (t *HTTPTransmitter) shouldRetry(err error) bool {
	httpErr, ok := err.(*HTTPError)
	if !ok {
		// Network errors and other non-HTTP errors should be retried
		return true
	}

	// Check if status code is in retryable list
	for _, retryableCode := range t.retryConfig.RetryableErrors {
		if httpErr.StatusCode == retryableCode {
			return true
		}
	}

	return false
}

// updateMetrics updates transmission metrics
func (t *HTTPTransmitter) updateMetrics(startTime time.Time, success bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	responseTime := time.Since(startTime)

	if success {
		t.successfulSends++
	} else {
		t.failedSends++
	}

	t.lastTransmitTime = time.Now()

	// Update average response time (simple moving average)
	if t.avgResponseTime == 0 {
		t.avgResponseTime = responseTime
	} else {
		t.avgResponseTime = (t.avgResponseTime + responseTime) / 2
	}
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
