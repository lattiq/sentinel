package hmac

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHMACAuthenticator(t *testing.T) {
	config := &Config{
		SecretKey:       "test-secret",
		Algorithm:       "sha256",
		HeaderName:      "X-Signature",
		TimestampHeader: "X-Timestamp",
		AuthWindow:      "5m",
	}

	auth := NewHMACAuthenticator(config)
	assert.NotNil(t, auth)
	assert.Equal(t, config, auth.config)
	assert.NotNil(t, auth.logger)
}

func TestGenerateClientSignature(t *testing.T) {
	secretKey := "test-secret"
	algorithm := "sha256"
	method := "POST"
	path := "/api/test"
	body := []byte(`{"test": "data"}`)
	timestamp := time.Now().Unix()

	signature, err := GenerateClientSignature(secretKey, algorithm, method, path, body, timestamp)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.Len(t, signature, 64) // SHA256 produces 64 character hex string

	// Same input should produce same signature
	signature2, err := GenerateClientSignature(secretKey, algorithm, method, path, body, timestamp)
	require.NoError(t, err)
	assert.Equal(t, signature, signature2)

	// Different input should produce different signature
	signature3, err := GenerateClientSignature(secretKey, algorithm, "GET", path, body, timestamp)
	require.NoError(t, err)
	assert.NotEqual(t, signature, signature3)
}

func TestGenerateClientSimpleSignature(t *testing.T) {
	secretKey := "test-secret"
	algorithm := "sha256"
	body := []byte(`{"test": "data"}`)

	signature, err := GenerateClientSimpleSignature(secretKey, algorithm, body)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.Len(t, signature, 64) // SHA256 produces 64 character hex string

	// Same input should produce same signature
	signature2, err := GenerateClientSimpleSignature(secretKey, algorithm, body)
	require.NoError(t, err)
	assert.Equal(t, signature, signature2)

	// Different input should produce different signature
	signature3, err := GenerateClientSimpleSignature(secretKey, algorithm, []byte("different"))
	require.NoError(t, err)
	assert.NotEqual(t, signature, signature3)
}

func TestAuthenticateWithValidSignature(t *testing.T) {
	config := &Config{
		SecretKey:       "test-secret",
		Algorithm:       "sha256",
		HeaderName:      "X-Signature",
		TimestampHeader: "X-Timestamp",
		AuthWindow:      "5m",
	}

	auth := NewHMACAuthenticator(config)
	method := "POST"
	path := "/api/test"
	body := []byte(`{"test": "data"}`)
	timestamp := time.Now().Unix()

	// Generate valid signature
	signature, err := auth.GenerateSignature(method, path, body, timestamp)
	require.NoError(t, err)

	// Should authenticate successfully
	err = auth.Authenticate(signature, method, path, body, timestamp)
	assert.NoError(t, err)
}

func TestAuthenticateWithInvalidSignature(t *testing.T) {
	config := &Config{
		SecretKey:       "test-secret",
		Algorithm:       "sha256",
		HeaderName:      "X-Signature",
		TimestampHeader: "X-Timestamp",
		AuthWindow:      "5m",
	}

	auth := NewHMACAuthenticator(config)
	method := "POST"
	path := "/api/test"
	body := []byte(`{"test": "data"}`)
	timestamp := time.Now().Unix()

	// Use invalid signature
	invalidSignature := "invalid-signature"

	// Should fail authentication
	err := auth.Authenticate(invalidSignature, method, path, body, timestamp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")
}

func TestAuthenticateWithExpiredTimestamp(t *testing.T) {
	config := &Config{
		SecretKey:       "test-secret",
		Algorithm:       "sha256",
		HeaderName:      "X-Signature",
		TimestampHeader: "X-Timestamp",
		AuthWindow:      "5m",
	}

	auth := NewHMACAuthenticator(config)
	method := "POST"
	path := "/api/test"
	body := []byte(`{"test": "data"}`)

	// Use timestamp from 10 minutes ago (outside 5m window)
	timestamp := time.Now().Add(-10 * time.Minute).Unix()

	// Generate signature with old timestamp
	signature, err := auth.GenerateSignature(method, path, body, timestamp)
	require.NoError(t, err)

	// Should fail due to expired timestamp
	err = auth.Authenticate(signature, method, path, body, timestamp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timestamp outside allowed window")
}

func TestAuthenticateWithSimpleSignature(t *testing.T) {
	config := &Config{
		SecretKey:       "test-secret",
		Algorithm:       "sha256",
		HeaderName:      "X-Signature",
		TimestampHeader: "X-Timestamp",
		AuthWindow:      "5m",
	}

	auth := NewHMACAuthenticator(config)
	method := "POST"
	path := "/api/test"
	body := []byte(`{"test": "data"}`)
	timestamp := time.Now().Unix()

	// Generate simple signature (payload only)
	signature, err := auth.GenerateSimpleSignature(body)
	require.NoError(t, err)

	// Should authenticate successfully with simple signature
	err = auth.Authenticate(signature, method, path, body, timestamp)
	assert.NoError(t, err)
}

func TestConfigGetAuthWindowDuration(t *testing.T) {
	tests := []struct {
		name     string
		window   string
		expected time.Duration
	}{
		{
			name:     "valid duration",
			window:   "10m",
			expected: 10 * time.Minute,
		},
		{
			name:     "invalid duration",
			window:   "invalid",
			expected: 10 * time.Minute, // fallback
		},
		{
			name:     "empty duration",
			window:   "",
			expected: 10 * time.Minute, // fallback
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{AuthWindow: tt.window}
			duration := config.getAuthWindowDuration()
			assert.Equal(t, tt.expected, duration)
		})
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	_, err := GenerateClientSignature("secret", "unsupported", "POST", "/path", []byte("body"), time.Now().Unix())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported HMAC algorithm")

	_, err = GenerateClientSimpleSignature("secret", "unsupported", []byte("body"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported HMAC algorithm")
}
