package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lattiq/sentinel/internal/hmac"
	"gopkg.in/yaml.v3"
)

// Config represents the complete agent configuration
type Config struct {
	Client      ClientConfig      `yaml:"client"`
	DataSources DataSourcesConfig `yaml:"data_sources"`
	Features    FeaturesConfig    `yaml:"features"`
	Batch       BatchConfig       `yaml:"batch"`
	Retry       RetryConfig       `yaml:"retry"`
	Health      HealthConfig      `yaml:"health"`
	Logging     LoggingConfig     `yaml:"logging"`
	AWS         AWSConfig         `yaml:"aws"`
	Watchtower  WatchtowerConfig  `yaml:"watchtower"`
}

// ClientConfig represents client identification
type ClientConfig struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Environment string `yaml:"environment"`
}

// DataSourcesConfig represents data source configurations
type DataSourcesConfig struct {
	QueryLogs  QueryLogsConfig  `yaml:"query_logs"`
	RDS        RDSConfig        `yaml:"rds"`
	CloudTrail CloudTrailConfig `yaml:"cloudtrail"`
}

// QueryLogsConfig represents CloudWatch query logs configuration
type QueryLogsConfig struct {
	Enabled       bool            `yaml:"enabled"`
	LogGroup      string          `yaml:"log_group"`
	StreamNames   []string        `yaml:"stream_names"`
	FilterPattern string          `yaml:"filter_pattern"`
	PollInterval  time.Duration   `yaml:"poll_interval"`
	BatchSize     int             `yaml:"batch_size"`
	StartTime     string          `yaml:"start_time"`
	LogFormat     LogFormatConfig `yaml:"log_format"`
}

// LogFormatConfig represents PostgreSQL log format configuration
type LogFormatConfig struct {
	LogLinePrefix    string `yaml:"log_line_prefix"`   // PostgreSQL log_line_prefix setting
	AutoDetect       bool   `yaml:"auto_detect"`       // Try to auto-detect format from log samples
	CloudWatchPrefix bool   `yaml:"cloudwatch_prefix"` // Whether logs have CloudWatch timestamp prefix
	LogLevelPrefix   bool   `yaml:"log_level_prefix"`  // Whether logs have LOG:/ERROR: prefix
}

// RDSConfig represents RDS monitoring configuration
type RDSConfig struct {
	Enabled             bool          `yaml:"enabled"`
	Instances           []string      `yaml:"instances"`
	MonitorAllInstances bool          `yaml:"monitor_all_instances"`
	Clusters            []string      `yaml:"clusters"`
	MonitorAllClusters  bool          `yaml:"monitor_all_clusters"`
	Region              string        `yaml:"region"`
	PollIntervals       PollIntervals `yaml:"poll_intervals"`
}

// PollIntervals represents different polling intervals for RDS
type PollIntervals struct {
	Instances time.Duration `yaml:"instances"`
	Clusters  time.Duration `yaml:"clusters"`
	Config    time.Duration `yaml:"config"`
	Snapshots time.Duration `yaml:"snapshots"`
}

// CloudTrailConfig represents CloudTrail monitoring configuration
type CloudTrailConfig struct {
	Enabled      bool          `yaml:"enabled"`
	S3Bucket     string        `yaml:"s3_bucket"`
	S3Prefix     string        `yaml:"s3_prefix"`
	StreamName   string        `yaml:"stream_name"`
	EventNames   []string      `yaml:"event_names"`
	PollInterval time.Duration `yaml:"poll_interval"`
	LookbackTime time.Duration `yaml:"lookback_time"`
}

// FeaturesConfig represents feature mapping configuration
type FeaturesConfig struct {
	Tables map[string]TableMapping `yaml:"tables"`
}

// TableMapping represents LattIQ feature mapping for a table
type TableMapping struct {
	Database    string   `yaml:"database,omitempty"` // Optional: specify database name for specificity
	Schema      string   `yaml:"schema"`
	LattIQCols  []string `yaml:"lattiq_columns"`
	PrimaryKey  []string `yaml:"primary_key"`
	Description string   `yaml:"description"`
}

// BatchConfig represents batching configuration
type BatchConfig struct {
	MaxSize        int           `yaml:"max_size" env:"BATCH_MAX_SIZE" default:"100"`
	MaxAge         time.Duration `yaml:"max_age" env:"BATCH_MAX_AGE" default:"30s"`
	Compression    bool          `yaml:"compression"`
	MaxPayloadSize int           `yaml:"max_payload_size_mb"`
}

// RetryConfig represents retry policy configuration
type RetryConfig struct {
	MaxRetries      int           `yaml:"max_retries"`
	InitialDelay    time.Duration `yaml:"initial_delay"`
	MaxDelay        time.Duration `yaml:"max_delay"`
	BackoffFactor   float64       `yaml:"backoff_factor"`
	RetryableErrors []string      `yaml:"retryable_errors"`
}

// HealthConfig represents health monitoring configuration
type HealthConfig struct {
	Enabled         bool            `yaml:"enabled"`
	ReportInterval  time.Duration   `yaml:"report_interval"`
	MetricRetention time.Duration   `yaml:"metric_retention"`
	Thresholds      AlertThresholds `yaml:"thresholds"`
}

// AlertThresholds represents health alert thresholds
type AlertThresholds struct {
	MemoryMB     int     `yaml:"memory_mb"`
	CPUPercent   float64 `yaml:"cpu_percent"`
	ErrorPercent float64 `yaml:"error_percent"`
	DiskMB       int     `yaml:"disk_mb"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	File       string `yaml:"file"`
	MaxSize    int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age_days"`
}

// AWSConfig represents AWS-specific configuration
type AWSConfig struct {
	Region  string `yaml:"region"`
	Profile string `yaml:"profile"`
}

// WatchtowerConfig defines LattIQ Watchtower configuration
type WatchtowerConfig struct {
	Endpoint    string        `yaml:"endpoint" env:"WATCHTOWER_ENDPOINT"`
	ClientID    string        `yaml:"client_id" env:"WATCHTOWER_CLIENT_ID"`
	Timeout     time.Duration `yaml:"timeout" env:"WATCHTOWER_TIMEOUT" default:"30s"`
	Compression bool          `yaml:"compression" env:"WATCHTOWER_COMPRESSION" default:"false"`
	HMAC        hmac.Config   `yaml:"hmac"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Client: ClientConfig{
			Environment: "production",
		},
		DataSources: DataSourcesConfig{
			QueryLogs: QueryLogsConfig{
				Enabled:      true,
				PollInterval: 30 * time.Second,
				BatchSize:    100,
				StartTime:    "latest",
				LogFormat: LogFormatConfig{
					LogLinePrefix:    "%t:%r:%u@%d:[%p]:",
					AutoDetect:       true,
					CloudWatchPrefix: true,
					LogLevelPrefix:   true,
				},
			},
			RDS: RDSConfig{
				Enabled: true,
				PollIntervals: PollIntervals{
					Instances: 15 * time.Minute,
					Clusters:  15 * time.Minute,
					Config:    30 * time.Minute,
					Snapshots: 30 * time.Minute,
				},
			},
			CloudTrail: CloudTrailConfig{
				Enabled:      true,
				PollInterval: 5 * time.Minute,
				LookbackTime: 15 * time.Minute,
				EventNames: []string{
					"CreateDBSnapshot",
					"CopyDBSnapshot",
					"ModifyDBSnapshotAttribute",
					"RestoreDBInstanceFromDBSnapshot",
					"RestoreDBInstanceToPointInTime",
					"CreateDBInstanceReadReplica",
					"ModifyDBInstance",
					"CreateDBCluster",
					"ModifyDBCluster",
					"DeleteDBCluster",
					"CreateDBClusterSnapshot",
					"CopyDBClusterSnapshot",
					"ModifyDBClusterSnapshotAttribute",
					"RestoreDBClusterFromSnapshot",
					"RestoreDBClusterToPointInTime",
					"CreateDBClusterReadReplica",
					"PromoteReadReplica",
					"StartExportTask",
					"CreateGlobalCluster",
				},
			},
		},
		Batch: BatchConfig{
			MaxSize:        100,
			MaxAge:         30 * time.Second,
			Compression:    true,
			MaxPayloadSize: 10,
		},
		Retry: RetryConfig{
			MaxRetries:    3,
			InitialDelay:  1 * time.Second,
			MaxDelay:      30 * time.Second,
			BackoffFactor: 2.0,
			RetryableErrors: []string{
				"TIMEOUT",
				"CONNECTION_ERROR",
				"SERVER_ERROR",
				"RATE_LIMITED",
			},
		},
		Health: HealthConfig{
			Enabled:         true,
			ReportInterval:  5 * time.Minute,
			MetricRetention: 24 * time.Hour,
			Thresholds: AlertThresholds{
				MemoryMB:     512,
				CPUPercent:   80.0,
				ErrorPercent: 5.0,
				DiskMB:       1024,
			},
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			MaxSize:    100,
			MaxBackups: 5,
			MaxAge:     7,
		},
		Watchtower: WatchtowerConfig{
			Endpoint:    "https://api.lattiq.com",
			ClientID:    "your-client-id",
			Timeout:     30 * time.Second,
			Compression: true,
			HMAC: hmac.Config{
				SecretKey:       "your-secret-key",
				Algorithm:       "sha256",
				HeaderName:      "X-Signature",
				TimestampHeader: "X-Timestamp",
				AuthWindow:      "5m",
			},
		},
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(filePath string) (*Config, error) {
	config := DefaultConfig()

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		// Expand environment variables
		expanded := os.ExpandEnv(string(data))

		if err := yaml.Unmarshal([]byte(expanded), config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Apply environment variable overrides
	config.applyEnvOverrides()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// applyEnvOverrides applies environment variable overrides
func (c *Config) applyEnvOverrides() {
	if val := os.Getenv("SENTINEL_CLIENT_ID"); val != "" {
		c.Client.ID = val
	}
	if val := os.Getenv("SENTINEL_CLIENT_NAME"); val != "" {
		c.Client.Name = val
	}
	if val := os.Getenv("SENTINEL_ENVIRONMENT"); val != "" {
		c.Client.Environment = val
	}
	if val := os.Getenv("SENTINEL_AWS_REGION"); val != "" {
		c.AWS.Region = val
		c.DataSources.RDS.Region = val
	}
	if val := os.Getenv("SENTINEL_LOG_LEVEL"); val != "" {
		c.Logging.Level = val
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Client.ID == "" {
		return fmt.Errorf("client.id is required")
	}
	if c.Client.Name == "" {
		return fmt.Errorf("client.name is required")
	}

	// Validate data sources
	if c.DataSources.QueryLogs.Enabled && c.DataSources.QueryLogs.LogGroup == "" {
		return fmt.Errorf("data_sources.query_logs.log_group is required when enabled")
	}
	if c.DataSources.RDS.Enabled && c.DataSources.RDS.Region == "" {
		return fmt.Errorf("data_sources.rds.region is required when enabled")
	}
	if c.DataSources.CloudTrail.Enabled {
		if c.DataSources.CloudTrail.S3Bucket == "" && c.DataSources.CloudTrail.StreamName == "" {
			return fmt.Errorf("either s3_bucket or stream_name is required for cloudtrail")
		}
	}

	// Validate logging level
	validLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLevels, strings.ToLower(c.Logging.Level)) {
		return fmt.Errorf("invalid logging level: %s", c.Logging.Level)
	}

	return nil
}

// Hash returns a hash of the configuration for change detection
func (c *Config) Hash() string {
	// Convert config to JSON bytes
	configBytes, err := json.Marshal(c)
	if err != nil {
		return ""
	}

	// Calculate SHA256 hash
	hash := sha256.Sum256(configBytes)
	return fmt.Sprintf("%x", hash)
}

// DetectChanges compares current config with previous config and returns changed sections
func (c *Config) DetectChanges(previousConfig *Config, previousHash string) ([]string, error) {
	if previousConfig == nil {
		return []string{"initial_config"}, nil
	}

	var changedSections []string

	// Compare major sections
	if !configSectionsEqual(c.Client, previousConfig.Client) {
		changedSections = append(changedSections, "client")
	}

	if !configSectionsEqual(c.DataSources, previousConfig.DataSources) {
		changedSections = append(changedSections, "data_sources")
	}
	if !configSectionsEqual(c.Features, previousConfig.Features) {
		changedSections = append(changedSections, "features")
	}
	if !configSectionsEqual(c.Batch, previousConfig.Batch) {
		changedSections = append(changedSections, "batch")
	}
	if !configSectionsEqual(c.Retry, previousConfig.Retry) {
		changedSections = append(changedSections, "retry")
	}
	if !configSectionsEqual(c.Health, previousConfig.Health) {
		changedSections = append(changedSections, "health")
	}
	if !configSectionsEqual(c.Logging, previousConfig.Logging) {
		changedSections = append(changedSections, "logging")
	}
	if !configSectionsEqual(c.AWS, previousConfig.AWS) {
		changedSections = append(changedSections, "aws")
	}
	if !configSectionsEqual(c.Watchtower, previousConfig.Watchtower) {
		changedSections = append(changedSections, "watchtower")
	}

	return changedSections, nil
}

// configSectionsEqual compares two config sections using JSON marshaling
func configSectionsEqual(a, b interface{}) bool {
	aBytes, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bBytes, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(aBytes) == string(bBytes)
}

// GetFeatureColumns returns all LattIQ feature columns across all tables
func (c *Config) GetFeatureColumns() map[string][]string {
	result := make(map[string][]string)
	for tableName, mapping := range c.Features.Tables {
		result[tableName] = mapping.LattIQCols
	}
	return result
}

// IsLattIQTable checks if a table contains LattIQ features
func (c *Config) IsLattIQTable(schema, table string) bool {
	tableName := fmt.Sprintf("%s.%s", schema, table)
	if _, exists := c.Features.Tables[tableName]; exists {
		return true
	}
	// Also check without schema prefix
	if _, exists := c.Features.Tables[table]; exists {
		return true
	}
	return false
}

// IsLattIQTableWithDatabase checks if a table contains LattIQ features for a specific database
func (c *Config) IsLattIQTableWithDatabase(database, schema, table string) bool {
	for _, mapping := range c.Features.Tables {
		// If database is specified in mapping, it must match
		if mapping.Database != "" && mapping.Database != database {
			continue
		}

		// Check schema and table match
		if mapping.Schema == schema {
			// Check if table name matches (either exact table name or full schema.table format)
			tableName := fmt.Sprintf("%s.%s", schema, table)
			for configuredTable := range c.Features.Tables {
				if configuredTable == table || configuredTable == tableName {
					if mappingForTable, exists := c.Features.Tables[configuredTable]; exists {
						if mappingForTable.Database == "" || mappingForTable.Database == database {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// GetLattIQColumns returns LattIQ columns for a specific table
func (c *Config) GetLattIQColumns(schema, table string) []string {
	tableName := fmt.Sprintf("%s.%s", schema, table)
	if mapping, exists := c.Features.Tables[tableName]; exists {
		return mapping.LattIQCols
	}
	// Also check without schema prefix
	if mapping, exists := c.Features.Tables[table]; exists {
		return mapping.LattIQCols
	}
	return nil
}

// GetLattIQColumnsWithDatabase returns LattIQ columns for a specific table in a specific database
func (c *Config) GetLattIQColumnsWithDatabase(database, schema, table string) []string {
	for configuredTable, mapping := range c.Features.Tables {
		// If database is specified in mapping, it must match
		if mapping.Database != "" && mapping.Database != database {
			continue
		}

		// Check schema match
		if mapping.Schema == schema {
			// Check table match (either exact table name or full schema.table format)
			tableName := fmt.Sprintf("%s.%s", schema, table)
			if configuredTable == table || configuredTable == tableName {
				return mapping.LattIQCols
			}
		}
	}
	return nil
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
