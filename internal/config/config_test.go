package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "production", cfg.Client.Environment)
	assert.Equal(t, 100, cfg.DataSources.QueryLogs.BatchSize)
	assert.Equal(t, 15*time.Minute, cfg.DataSources.RDS.PollIntervals.Instances)
	assert.Equal(t, true, cfg.Batch.Compression)
	assert.Equal(t, 3, cfg.Retry.MaxRetries)
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		modifier  func(*Config)
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid config",
			modifier: func(c *Config) {
				c.Client.ID = "test-client"
				c.Client.Name = "Test Client"
				c.DataSources.QueryLogs.LogGroup = "/aws/test"
				c.DataSources.RDS.Region = "us-east-1"
				c.DataSources.CloudTrail.S3Bucket = "test-bucket"
			},
			expectErr: false,
		},
		{
			name: "missing client ID",
			modifier: func(c *Config) {
				c.Client.Name = "Test Client"
			},
			expectErr: true,
			errMsg:    "client.id is required",
		},
		{
			name: "invalid logging level",
			modifier: func(c *Config) {
				c.Client.ID = "test-client"
				c.Client.Name = "Test Client"
				c.DataSources.QueryLogs.LogGroup = "/aws/test"
				c.DataSources.RDS.Region = "us-east-1"
				c.DataSources.CloudTrail.S3Bucket = "test-bucket"
				c.Logging.Level = "invalid"
			},
			expectErr: true,
			errMsg:    "invalid logging level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modifier(cfg)

			err := cfg.Validate()
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEnvOverrides(t *testing.T) {
	// Set environment variables
	os.Setenv("SENTINEL_CLIENT_ID", "env-client-id")
	os.Setenv("SENTINEL_CLIENT_NAME", "Env Client Name")
	os.Setenv("SENTINEL_ENVIRONMENT", "development")
	os.Setenv("SENTINEL_LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("SENTINEL_CLIENT_ID")
		os.Unsetenv("SENTINEL_CLIENT_NAME")
		os.Unsetenv("SENTINEL_ENVIRONMENT")
		os.Unsetenv("SENTINEL_LOG_LEVEL")
	}()

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	assert.Equal(t, "env-client-id", cfg.Client.ID)
	assert.Equal(t, "Env Client Name", cfg.Client.Name)
	assert.Equal(t, "development", cfg.Client.Environment)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestFeatureMethods(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Features.Tables = map[string]TableMapping{
		"customers": {
			Schema:      "public",
			LattIQCols:  []string{"risk_score", "churn_prob"},
			PrimaryKey:  []string{"customer_id"},
			Description: "Customer table",
		},
		"transactions": {
			Schema:      "public",
			LattIQCols:  []string{"anomaly_score"},
			PrimaryKey:  []string{"tx_id"},
			Description: "Transaction table",
		},
	}

	// Test GetFeatureColumns
	features := cfg.GetFeatureColumns()
	assert.Equal(t, 2, len(features))
	assert.Equal(t, []string{"risk_score", "churn_prob"}, features["customers"])
	assert.Equal(t, []string{"anomaly_score"}, features["transactions"])

	// Test IsLattIQTable
	assert.True(t, cfg.IsLattIQTable("public", "customers"))
	assert.True(t, cfg.IsLattIQTable("", "customers")) // without schema
	assert.False(t, cfg.IsLattIQTable("public", "unknown"))

	// Test GetLattIQColumns
	cols := cfg.GetLattIQColumns("public", "customers")
	assert.Equal(t, []string{"risk_score", "churn_prob"}, cols)

	cols = cfg.GetLattIQColumns("", "customers") // without schema
	assert.Equal(t, []string{"risk_score", "churn_prob"}, cols)

	cols = cfg.GetLattIQColumns("public", "unknown")
	assert.Nil(t, cols)
}

func TestConfigHash(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg1.Client.ID = "test-client"

	cfg2 := DefaultConfig()
	cfg2.Client.ID = "test-client"

	cfg3 := DefaultConfig()
	cfg3.Client.ID = "different-client"

	hash1 := cfg1.Hash()
	hash2 := cfg2.Hash()
	hash3 := cfg3.Hash()

	// Same config should produce same hash
	assert.Equal(t, hash1, hash2)

	// Different config should produce different hash
	assert.NotEqual(t, hash1, hash3)

	// Hash should be non-empty
	assert.NotEmpty(t, hash1)
}
