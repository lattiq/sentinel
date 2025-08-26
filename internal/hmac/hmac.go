package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

// Config represents HMAC authentication configuration
type Config struct {
	SecretKey       string `json:"secret_key" yaml:"secret_key"`
	Algorithm       string `json:"algorithm" yaml:"algorithm"` // "sha256", "sha512"
	HeaderName      string `json:"header_name" yaml:"header_name"`
	TimestampHeader string `json:"timestamp_header" yaml:"timestamp_header"`
	AuthWindow      string `json:"auth_window" yaml:"auth_window"` // Allowed time window for request authentication
}

func (c *Config) getAuthWindowDuration() time.Duration {
	duration, err := time.ParseDuration(c.AuthWindow)
	if err != nil {
		return 10 * time.Minute // default fallback
	}
	return duration
}

// Authenticator handles HMAC-based authentication
type Authenticator struct {
	config *Config
	logger *logrus.Entry
}

// NewHMACAuthenticator creates a new HMAC authenticator
func NewHMACAuthenticator(config *Config) *Authenticator {
	logger := logrus.WithFields(logrus.Fields{
		"component": "hmac_authenticator",
		"algorithm": config.Algorithm,
	})

	return &Authenticator{
		config: config,
		logger: logger,
	}
}

// AuthenticateRequest validates the HMAC signature of an incoming request
func (h *Authenticator) AuthenticateRequest(r *http.Request, body []byte) error {
	// Get signature from header
	signature := r.Header.Get(h.config.HeaderName)
	if signature == "" {
		return fmt.Errorf("missing signature header: %s", h.config.HeaderName)
	}

	// Get timestamp from header
	timestampStr := r.Header.Get(h.config.TimestampHeader)
	if timestampStr == "" {
		return fmt.Errorf("missing timestamp header: %s", h.config.TimestampHeader)
	}

	// Parse timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp format: %w", err)
	}

	if err := h.Authenticate(signature, r.Method, r.URL.Path, body, timestamp); err != nil {
		return err
	}

	return nil
}

func (h *Authenticator) Authenticate(signature, method, path string, body []byte, timestamp int64) error {
	// Check timestamp window
	currentTime := time.Now().Unix()
	timeDiff := currentTime - timestamp
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}

	if timeDiff > int64(h.config.getAuthWindowDuration().Seconds()) {
		return fmt.Errorf("request timestamp outside allowed window")
	}

	// Generate expected signature
	expectedSignature, err := h.GenerateSignature(method, path, body, timestamp)
	if err != nil {
		return fmt.Errorf("failed to generate signature: %w", err)
	}

	expectedSimpleSignature, err := h.GenerateSimpleSignature(body)
	if err != nil {
		return fmt.Errorf("failed to generate simple signature: %w", err)
	}

	// Compare signatures - try both methods for compatibility
	validSignature := hmac.Equal([]byte(signature), []byte(expectedSignature)) ||
		hmac.Equal([]byte(signature), []byte(expectedSimpleSignature))

	if !validSignature {
		h.logger.WithFields(logrus.Fields{
			"method":          method,
			"path":            path,
			"expected_full":   expectedSignature,
			"expected_simple": expectedSimpleSignature,
			"received":        signature,
			"timestamp":       timestamp,
		}).Warn("HMAC signature mismatch")
		return fmt.Errorf("invalid signature")
	}

	h.logger.WithFields(logrus.Fields{
		"method":    method,
		"path":      path,
		"timestamp": timestamp,
	}).Debug("HMAC signature validated")

	return nil
}

// GenerateSignature generates an HMAC signature for a request
func (h *Authenticator) GenerateSignature(method, path string, body []byte, timestamp int64) (string, error) {
	return GenerateClientSignature(h.config.SecretKey, h.config.Algorithm, method, path, body, timestamp)
}

// GenerateSimpleSignature generates a simple HMAC signature for payload only (Sentinel compatibility)
func (h *Authenticator) GenerateSimpleSignature(body []byte) (string, error) {
	return GenerateClientSimpleSignature(h.config.SecretKey, h.config.Algorithm, body)
}

// GenerateClientSignature is a helper function for clients to generate signatures
func GenerateClientSignature(secretKey, algorithm, method, path string, body []byte, timestamp int64) (string, error) {
	var hasher hash.Hash
	switch algorithm {
	case "sha256":
		hasher = hmac.New(sha256.New, []byte(secretKey))
	case "sha512":
		hasher = hmac.New(sha512.New, []byte(secretKey))
	default:
		return "", fmt.Errorf("unsupported HMAC algorithm: %s", algorithm)
	}

	// Create string to sign: ALGORITHM\nMETHOD\nPATH\nTIMESTAMP\nBODY
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%d\n%s",
		algorithm, method, path, timestamp, string(body))

	// Generate signature
	hasher.Write([]byte(stringToSign))
	signature := hex.EncodeToString(hasher.Sum(nil))

	return signature, nil
}

// GenerateClientSimpleSignature is a helper function for clients to generate signatures for payload only
func GenerateClientSimpleSignature(secretKey, algorithm string, body []byte) (string, error) {
	var hasher hash.Hash
	switch algorithm {
	case "sha256":
		hasher = hmac.New(sha256.New, []byte(secretKey))
	case "sha512":
		hasher = hmac.New(sha512.New, []byte(secretKey))
	default:
		return "", fmt.Errorf("unsupported HMAC algorithm: %s", algorithm)
	}

	// Generate signature
	hasher.Write([]byte(body))
	signature := hex.EncodeToString(hasher.Sum(nil))

	return signature, nil
}
