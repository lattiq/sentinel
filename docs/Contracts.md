# Data Abuse Monitoring System - Contracts

## Document Overview

This document defines the complete contract specification between the monitoring agent (deployed in client infrastructure) and the centralized monitoring service (LattIQ infrastructure) for the Data Abuse Monitoring System.

**Version**: 1.0  
**Last Updated**: June 25, 2025  
**Target Audience**: Backend Engineers, System Architects, DevOps Teams

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Authentication & Security](#authentication--security)
3. [Message Envelope](#message-envelope)
4. [Data Structure Contracts](#data-structure-contracts)
5. [HTTP API Specification](#http-api-specification)
6. [Agent Configuration](#agent-configuration)
7. [Error Handling](#error-handling)
8. [Performance Requirements](#performance-requirements)

---

## System Architecture

### Component Overview

```
Client Infrastructure                    LattIQ Infrastructure
┌─────────────────────┐                 ┌─────────────────────┐
│   Monitoring Agent  │ ──HTTPS────────▶│  Monitoring Service │
│                     │                 │                     │
│ ┌─────────────────┐ │                 │ ┌─────────────────┐ │
│ │ Data Collectors │ │                 │ │ Data Ingestion  │ │
│ │ - Query Logs    │ │                 │ │ - Validation    │ │
│ │ - RDS API       │ │                 │ │ - Processing    │ │
│ │ - CloudTrail    │ │                 │ │ - Storage       │ │
│ └─────────────────┘ │                 │ └─────────────────┘ │
│                     │                 │                     │
│ ┌─────────────────┐ │                 │ ┌─────────────────┐ │
│ │ Data Processor  │ │                 │ │ Analysis Engine │ │
│ │ - SQL Parsing   │ │                 │ │ - Pattern Det.  │ │
│ │ - Normalization │ │                 │ │ - Anomaly Det.  │ │
│ │ - Batching      │ │                 │ │ - Alerting      │ │
│ └─────────────────┘ │                 │ └─────────────────┘ │
└─────────────────────┘                 └─────────────────────┘
```

### Data Flow

1. **Collection**: Agent collects data from PostgreSQL logs, RDS APIs, CloudTrail
2. **Processing**: Agent parses, normalizes, and batches data
3. **Transmission**: HTTPS POST to monitoring service with authentication
4. **Ingestion**: Service validates, processes, and stores data
5. **Analysis**: Service analyzes patterns and generates alerts

---

## Authentication & Security

### Authentication Headers

```go
type AuthHeader struct {
    ClientID     string `json:"client_id"`     // Unique client identifier
    APIKey       string `json:"api_key"`       // Rotating API key
    Timestamp    int64  `json:"timestamp"`     // Unix timestamp (UTC)
    Signature    string `json:"signature"`     // HMAC-SHA256 signature
}
```

### Signature Generation

```go
// Signature calculation
func generateSignature(clientID, apiKey string, timestamp int64, payload []byte) string {
    message := fmt.Sprintf("%s:%s:%d:%s",
        clientID, apiKey, timestamp, base64.StdEncoding.EncodeToString(payload))

    mac := hmac.New(sha256.New, []byte(secretKey))
    mac.Write([]byte(message))
    return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
```

### Security Requirements

- **Transport**: TLS 1.3 minimum for all communications
- **Authentication**: HMAC-SHA256 signatures with rotating API keys
- **Timestamp Validation**: Requests must be within 300 seconds of current time
- **Rate Limiting**: 1000 requests per minute per client
- **Payload Encryption**: Optional AES-256-GCM for sensitive payloads

---

## Message Envelope

### Base Message Structure

```go
type MonitoringMessage struct {
    MessageID    string                 `json:"message_id"`    // UUID v4 for deduplication
    ClientID     string                 `json:"client_id"`     // Client identifier
    Timestamp    int64                  `json:"timestamp"`     // Unix timestamp (UTC)
    MessageType  string                 `json:"message_type"`  // Data source type
    BatchSize    int                    `json:"batch_size"`    // Number of events in batch
    Data         interface{}            `json:"data"`          // Polymorphic data payload
    Metadata     map[string]interface{} `json:"metadata"`      // Additional context
    Version      string                 `json:"version"`       // Contract version (e.g., "1.0")
}
```

### Message Types

| Type            | Description                 | Frequency  | Priority |
| --------------- | --------------------------- | ---------- | -------- |
| `query_logs`    | PostgreSQL query log events | Real-time  | High     |
| `rds_instances` | RDS instance configuration  | 15 minutes | Medium   |
| `rds_config`    | RDS parameter changes       | 30 minutes | Medium   |
| `rds_snapshots` | Snapshot operations         | 30 minutes | Medium   |
| `cloudtrail`    | AWS CloudTrail events       | Real-time  | High     |
| `health`        | Component health status     | 5 minutes  | Low      |
| `agent_health`  | Agent status and metrics    | 5 minutes  | Low      |
| `config`        | Configuration tracking      | On-demand  | Medium   |

### Metadata Fields

```go
type MessageMetadata struct {
    AgentVersion    string `json:"agent_version"`    // Monitoring agent version
    AWSRegion       string `json:"aws_region"`       // AWS region
    Environment     string `json:"environment"`      // prod, staging, dev
    CollectionTime  int64  `json:"collection_time"`  // When data was collected
    ProcessingTime  int64  `json:"processing_time"`  // When processing completed
    Compressed      bool   `json:"compressed"`       // Is payload compressed
    CompressionType string `json:"compression_type"` // gzip, none
}
```

---

## Data Structure Contracts

### 1. PostgreSQL Query Log Events

```go
type QueryLogEvent struct {
    // Basic Query Information
    Timestamp       int64             `json:"timestamp"`         // When query executed (Unix timestamp)
    DatabaseName    string            `json:"database_name"`     // Target database name
    UserName        string            `json:"user_name"`         // Database user
    ApplicationName string            `json:"application_name"`  // Client application name

    // Query Analysis
    QueryHash       string            `json:"query_hash"`        // SHA-256 of normalized query
    QueryPattern    string            `json:"query_pattern"`     // Parameterized query
    Duration        int64             `json:"duration_ms"`       // Execution time (milliseconds)
    ConnectionID    string            `json:"connection_id"`     // Session identifier
    QueryType       string            `json:"query_type"`        // SELECT, INSERT, CREATE, etc.
    RowsAffected    *int64            `json:"rows_affected,omitempty"` // Rows returned/modified

    // LattIQ-Specific Analysis
    TableAccess     []TableAccess     `json:"table_access"`      // Parsed table/column access

    // Replication Detection
    IsReplication   bool              `json:"is_replication"`    // Is logical replication command
    ReplicationOp   *ReplicationOp    `json:"replication_op,omitempty"` // Replication details

    // Additional Context
    ClientIP        string            `json:"client_ip,omitempty"`     // Client IP address
    SSLUsed         bool              `json:"ssl_used"`                // TLS connection used
    QuerySize       int               `json:"query_size_bytes"`        // Query text size
}

type TableAccess struct {
    Schema      string   `json:"schema"`       // Database schema
    Table       string   `json:"table"`        // Table name
    Columns     []string `json:"columns"`      // Columns accessed (["*"] for SELECT *)
    AccessType  string   `json:"access_type"`  // SELECT, INSERT, UPDATE, DELETE, CREATE, DROP
    IsLattIQ    bool     `json:"is_lattiq"`    // Contains LattIQ feature columns
    LattIQCols  []string `json:"lattiq_cols"`  // Specific LattIQ columns accessed
    RowEstimate *int64   `json:"row_estimate,omitempty"` // Estimated rows accessed
}

type ReplicationOp struct {
    Command      string   `json:"command"`       // CREATE_PUBLICATION, CREATE_SUBSCRIPTION, etc.
    ObjectName   string   `json:"object_name"`   // Publication/subscription name
    TargetTables []string `json:"target_tables,omitempty"` // Tables in publication
    SlotName     string   `json:"slot_name,omitempty"`     // Replication slot name
    Options      map[string]string `json:"options,omitempty"` // Additional options
}
```

### 2. RDS Infrastructure Events

```go
type RDSInstanceEvent struct {
    // Instance Identification
    InstanceID       string    `json:"instance_id"`         // RDS instance identifier
    InstanceClass    string    `json:"instance_class"`      // db.t3.micro, etc.
    Engine           string    `json:"engine"`              // postgres
    EngineVersion    string    `json:"engine_version"`      // 14.9, etc.

    // Instance Status
    Status           string    `json:"status"`              // available, creating, etc.
    LastModified     int64     `json:"last_modified"`       // Last modification time

    // Replication Configuration
    ReadReplicaSource            *string   `json:"read_replica_source,omitempty"`
    ReadReplicas                 []string  `json:"read_replicas"`

    // Backup Configuration
    RestoreTime                  *int64    `json:"restore_time,omitempty"`
    BackupRetentionPeriod        int       `json:"backup_retention_period"`
    PreferredBackupWindow        string    `json:"preferred_backup_window"`
    PreferredMaintenanceWindow   string    `json:"preferred_maintenance_window"`

    // High Availability
    MultiAZ                      bool      `json:"multi_az"`
    AvailabilityZone            string    `json:"availability_zone"`

    // Storage
    AllocatedStorage            int       `json:"allocated_storage"`
    StorageType                 string    `json:"storage_type"`
    StorageEncrypted            bool      `json:"storage_encrypted"`

    // Networking
    VpcId                       string    `json:"vpc_id"`
    SubnetGroup                 string    `json:"subnet_group"`
    PubliclyAccessible          bool      `json:"publicly_accessible"`
}

type RDSConfigEvent struct {
    InstanceID       string              `json:"instance_id"`
    ParameterGroup   string              `json:"parameter_group"`
    Parameters       []ConfigParameter   `json:"parameters"`
    LastModified     int64               `json:"last_modified"`
    ApplyMethod      string              `json:"apply_method"`      // immediate, pending-reboot
}

type ConfigParameter struct {
    Name          string `json:"name"`            // Parameter name
    Value         string `json:"value"`           // Current value
    DefaultValue  string `json:"default_value"`   // Default value
    IsModifiable  bool   `json:"is_modifiable"`   // Can be changed
    IsReplication bool   `json:"is_replication"`  // Replication-related parameter
    IsBackup      bool   `json:"is_backup"`       // Backup-related parameter
    ApplyType     string `json:"apply_type"`      // static, dynamic
    DataType      string `json:"data_type"`       // string, integer, boolean
}

type RDSSnapshotEvent struct {
    // Snapshot Identification
    SnapshotID       string `json:"snapshot_id"`     // Snapshot identifier
    InstanceID       string `json:"instance_id"`     // Source instance

    // Snapshot Properties
    SnapshotType     string `json:"snapshot_type"`   // manual, automated
    CreateTime       int64  `json:"create_time"`     // Creation timestamp
    DatabaseTime     int64  `json:"database_time"`   // Database state timestamp
    Status           string `json:"status"`          // available, creating, etc.

    // Storage Information
    AllocatedStorage int    `json:"allocated_storage"` // Storage size (GB)
    Encrypted        bool   `json:"encrypted"`         // Encryption status
    KmsKeyId         string `json:"kms_key_id,omitempty"` // KMS key

    // Additional Properties
    Engine           string `json:"engine"`            // Database engine
    EngineVersion    string `json:"engine_version"`    // Engine version
    LicenseModel     string `json:"license_model"`     // License information
    Port             int    `json:"port"`              // Database port
}
```

### 3. CloudTrail Events

```go
type CloudTrailEvent struct {
    // Event Identification
    EventID          string                 `json:"event_id"`         // Unique event ID
    EventName        string                 `json:"event_name"`       // API action name
    EventTime        int64                  `json:"event_time"`       // Event timestamp
    EventSource      string                 `json:"event_source"`     // AWS service (rds.amazonaws.com)
    EventVersion     string                 `json:"event_version"`    // CloudTrail event version

    // Request Context
    AWSRegion        string                 `json:"aws_region"`       // AWS region
    SourceIP         string                 `json:"source_ip"`        // Source IP address
    UserAgent        string                 `json:"user_agent"`       // User agent string

    // Identity Information
    UserIdentity     UserIdentity           `json:"user_identity"`    // Who made the request

    // Request/Response Data
    RequestParams    map[string]interface{} `json:"request_parameters"`  // API request parameters
    ResponseElements map[string]interface{} `json:"response_elements"`   // API response data

    // Additional Context
    ReadOnly         bool                   `json:"read_only"`           // Read-only operation
    ResourceName     string                 `json:"resource_name,omitempty"` // Affected resource
    ErrorCode        string                 `json:"error_code,omitempty"`    // Error if failed
    ErrorMessage     string                 `json:"error_message,omitempty"` // Error details
}

type UserIdentity struct {
    Type            string `json:"type"`              // Root, IAMUser, AssumedRole, etc.
    PrincipalId     string `json:"principal_id"`      // Principal identifier
    UserName        string `json:"user_name"`         // User name
    ARN             string `json:"arn"`               // Full ARN
    AccountId       string `json:"account_id"`        // AWS account ID
    AccessKeyId     string `json:"access_key_id,omitempty"` // Access key used
    SessionContext  *SessionContext `json:"session_context,omitempty"` // Session info
}

type SessionContext struct {
    SessionIssuer   SessionIssuer `json:"session_issuer"`
    CreationDate    int64         `json:"creation_date"`
    MFAAuthenticated bool         `json:"mfa_authenticated"`
}

type SessionIssuer struct {
    Type        string `json:"type"`
    PrincipalId string `json:"principal_id"`
    ARN         string `json:"arn"`
    UserName    string `json:"user_name"`
}
```

### 4. Agent Health Events

```go
type AgentHealthEvent struct {
    // Agent Information
    AgentVersion     string            `json:"agent_version"`      // Semantic version
    StartTime        int64             `json:"start_time"`         // Agent start timestamp
    Uptime           int64             `json:"uptime_seconds"`     // Current uptime

    // Data Collection Status
    LastCollection   map[string]int64  `json:"last_collection"`    // source -> last collection time
    CollectionCounts map[string]int64  `json:"collection_counts"`  // source -> total collected
    ErrorCounts      map[string]int    `json:"error_counts"`       // source -> error count

    // Configuration
    ConfigHash       string            `json:"config_hash"`        // SHA-256 of current config
    ConfigVersion    string            `json:"config_version"`     // Config version
    LastConfigUpdate int64             `json:"last_config_update"` // Last config change

    // System Resources
    MemoryUsage      int64             `json:"memory_usage_bytes"` // Current memory usage
    CPUUsage         float64           `json:"cpu_usage_percent"`  // Current CPU usage
    DiskUsage        int64             `json:"disk_usage_bytes"`   // Disk space used

    // Performance Metrics
    BatchMetrics     BatchMetrics      `json:"batch_metrics"`      // Batching statistics
    APIMetrics       APIMetrics        `json:"api_metrics"`        // API call statistics

    // Health Status
    Status           string            `json:"status"`             // healthy, degraded, error
    Issues           []HealthIssue     `json:"issues,omitempty"`   // Current issues
}

type BatchMetrics struct {
    TotalBatches     int64   `json:"total_batches"`      // Total batches sent
    AvgBatchSize     float64 `json:"avg_batch_size"`     // Average events per batch
    AvgBatchAge      float64 `json:"avg_batch_age_ms"`   // Average batch age
    CompressionRatio float64 `json:"compression_ratio"`  // Compression effectiveness
}

type APIMetrics struct {
    TotalRequests    int64   `json:"total_requests"`     // Total API requests
    SuccessRate      float64 `json:"success_rate"`       // Success percentage
    AvgResponseTime  float64 `json:"avg_response_time_ms"` // Average response time
    RetryRate        float64 `json:"retry_rate"`         // Retry percentage
}

type HealthIssue struct {
    Type        string `json:"type"`        // connection, permission, resource
    Severity    string `json:"severity"`    // low, medium, high, critical
    Message     string `json:"message"`     // Human-readable description
    FirstSeen   int64  `json:"first_seen"`  // When issue first occurred
    LastSeen    int64  `json:"last_seen"`   // When issue last occurred
    Count       int    `json:"count"`       // Number of occurrences
}
```

---

## HTTP API Specification

### Base URL Structure

```
Development: http://localhost:8080
Production:  https://api.lattiq.com
```

### Endpoints

#### 1. Event Ingestion

```http
POST /sentinel/api/v1/events
Content-Type: application/json
```

**Request Body**:

```json
{
  "message_id": "uuid-v4",
  "client_id": "client-12345",
  "timestamp": 1706188800,
  "message_type": "query_logs",
  "batch_size": 50,
  "data": {
    "events": [...],
    "batch_metadata": {...}
  },
  "metadata": {
    "agent_version": "1.0.0",
    "aws_region": "us-east-1",
    "environment": "production"
  },
  "version": "1.0"
}
```

**Response Body**:

```json
{
  "status": "accepted",
  "message": "Data received successfully"
}
```

#### 2. Batch Event Ingestion

```http
POST /watchtower/v1/events/batch
Content-Type: application/json
```

**Request Body**:

```json
{
  "client_id": "client-12345",
  "timestamp": 1706188800,
  "batch_size": 2,
  "messages": [
    {
      "message_id": "msg-1",
      "client_id": "client-12345",
      "timestamp": 1706188800,
      "message_type": "query_logs",
      "batch_size": 1,
      "data": {...},
      "metadata": {...},
      "version": "1.0"
    },
    {
      "message_id": "msg-2",
      "client_id": "client-12345",
      "timestamp": 1706188805,
      "message_type": "rds_instances",
      "batch_size": 1,
      "data": {...},
      "metadata": {...},
      "version": "1.0"
    }
  ],
  "metadata": {
    "transmission_time": 1706188860,
    "batch_count": 2
  }
}
```

#### 3. Agent Health Check

```http
POST /api/v1/sentinel/health
Content-Type: application/json
```

#### 4. Configuration Sync

```http
GET /api/v1/sentinel/config
Content-Type: application/json
```

**Response**:

```json
{
  "config_version": "1.2.0",
  "config_hash": "sha256-hash",
  "updated_at": 1706188800,
  "config": {
    "data_sources": {...},
    "feature_mapping": {...},
    "batch_settings": {...}
  }
}
```

### HTTP Status Codes

| Status | Meaning              | Action                         |
| ------ | -------------------- | ------------------------------ |
| 200    | Success              | Continue normal operation      |
| 202    | Accepted             | Data queued for processing     |
| 400    | Bad Request          | Fix request format/data        |
| 401    | Unauthorized         | Check authentication           |
| 403    | Forbidden            | Check permissions              |
| 409    | Conflict             | Duplicate message_id           |
| 413    | Payload Too Large    | Reduce batch size              |
| 422    | Unprocessable Entity | Fix data validation errors     |
| 429    | Rate Limited         | Implement backoff              |
| 500    | Server Error         | Retry with exponential backoff |
| 503    | Service Unavailable  | Retry with backoff             |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid message format",
    "details": [
      {
        "field": "data.events[0].timestamp",
        "error": "timestamp is required",
        "code": "MISSING_FIELD"
      }
    ]
  },
  "request_id": "req-uuid-v4",
  "timestamp": 1706188800
}
```

---

## Agent Configuration

### Configuration File Structure

```go
type AgentConfig struct {
    // Client Identification
    ClientID           string                    `json:"client_id"`
    ClientName         string                    `json:"client_name"`
    Environment        string                    `json:"environment"`        // prod, staging, dev

    // Service Connection
    ServiceEndpoint    string                    `json:"service_endpoint"`
    APICredentials     APICredentials           `json:"api_credentials"`

    // Data Sources
    DataSources        DataSourceConfig         `json:"data_sources"`

    // LattIQ Feature Mapping
    FeatureMapping     FeatureMappingConfig     `json:"feature_mapping"`

    // Processing Settings
    BatchSettings      BatchSettings            `json:"batch_settings"`
    RetryPolicy        RetryPolicy              `json:"retry_policy"`

    // Monitoring Settings
    HealthCheck        HealthCheckConfig        `json:"health_check"`
    Logging            LoggingConfig            `json:"logging"`
}

type APICredentials struct {
    APIKey          string `json:"api_key"`
    SecretKey       string `json:"secret_key"`
    TokenEndpoint   string `json:"token_endpoint,omitempty"`
    RefreshInterval int    `json:"refresh_interval_minutes"`
}

type DataSourceConfig struct {
    QueryLogs   QueryLogConfig   `json:"query_logs"`
    RDS         RDSConfig        `json:"rds"`
    CloudTrail  CloudTrailConfig `json:"cloudtrail"`
}

type QueryLogConfig struct {
    Enabled         bool     `json:"enabled"`
    LogGroupName    string   `json:"log_group_name"`      // CloudWatch log group
    StreamNames     []string `json:"stream_names"`        // Specific streams
    FilterPattern   string   `json:"filter_pattern"`      // CloudWatch filter
    PollInterval    int      `json:"poll_interval_seconds"`
    BatchSize       int      `json:"batch_size"`
    StartTime       string   `json:"start_time"`          // "latest", "earliest", ISO timestamp
}

type RDSConfig struct {
    Enabled              bool     `json:"enabled"`
    InstanceIdentifiers  []string `json:"instance_identifiers"`  // Specific instances to monitor
    MonitorAllInstances  bool     `json:"monitor_all_instances"`  // Monitor all in account
    PollInterval         int      `json:"poll_interval_seconds"`
    ConfigPollInterval   int      `json:"config_poll_interval_seconds"`
    SnapshotPollInterval int      `json:"snapshot_poll_interval_seconds"`
    Region               string   `json:"region"`
}

type CloudTrailConfig struct {
    Enabled       bool     `json:"enabled"`
    S3Bucket      string   `json:"s3_bucket,omitempty"`      // S3 bucket for logs
    S3Prefix      string   `json:"s3_prefix,omitempty"`      // S3 key prefix
    StreamName    string   `json:"stream_name,omitempty"`    // CloudWatch stream
    EventNames    []string `json:"event_names"`              // Specific events to monitor
    PollInterval  int      `json:"poll_interval_seconds"`
    LookbackTime  int      `json:"lookback_time_minutes"`    // How far back to check
}

type FeatureMappingConfig struct {
    Tables map[string]TableMapping `json:"tables"` // table_name -> mapping
}

type TableMapping struct {
    Schema      string   `json:"schema"`
    LattIQCols  []string `json:"lattiq_columns"`    // LattIQ feature column names
    PrimaryKey  []string `json:"primary_key"`       // Primary key columns
    Description string   `json:"description"`       // Table description
}

type BatchSettings struct {
    MaxBatchSize     int   `json:"max_batch_size"`     // Max events per batch
    MaxBatchAge      int   `json:"max_batch_age_sec"`  // Max time to hold batch
    CompressionLevel int   `json:"compression_level"`   // 0=none, 1-9=gzip levels
    MaxPayloadSize   int   `json:"max_payload_size_mb"` // Max payload size
}

type RetryPolicy struct {
    MaxRetries      int     `json:"max_retries"`
    InitialDelay    int     `json:"initial_delay_ms"`
    MaxDelay        int     `json:"max_delay_ms"`
    BackoffFactor   float64 `json:"backoff_factor"`
    RetryableErrors []string `json:"retryable_errors"`
}

type HealthCheckConfig struct {
    Enabled          bool `json:"enabled"`
    ReportInterval   int  `json:"report_interval_seconds"`
    MetricRetention  int  `json:"metric_retention_hours"`
    AlertThresholds  AlertThresholds `json:"alert_thresholds"`
}

type AlertThresholds struct {
    MemoryUsageMB    int     `json:"memory_usage_mb"`
    CPUUsagePercent  float64 `json:"cpu_usage_percent"`
    ErrorRatePercent float64 `json:"error_rate_percent"`
    DiskUsageMB      int     `json:"disk_usage_mb"`
}

type LoggingConfig struct {
    Level        string `json:"level"`         // debug, info, warn, error
    Format       string `json:"format"`        // json, text
    File         string `json:"file,omitempty"` // Log file path
    MaxSize      int    `json:"max_size_mb"`   // Max log file size
    MaxBackups   int    `json:"max_backups"`   // Number of backup files
    MaxAge       int    `json:"max_age_days"`  // Max age of log files
}
```

### Example Configuration

```json
{
  "client_id": "lattiq-client-12345",
  "client_name": "Acme Analytics Corp",
  "environment": "production",
  "service_endpoint": "https://monitoring-api.lattiq.com/api/v1",
  "api_credentials": {
    "api_key": "ak_prod_abcd1234",
    "secret_key": "sk_prod_secret_key_xyz789",
    "refresh_interval_minutes": 60
  },
  "data_sources": {
    "query_logs": {
      "enabled": true,
      "log_group_name": "/aws/rds/instance/prod-analytics/postgresql",
      "stream_names": [],
      "filter_pattern": "",
      "poll_interval_seconds": 30,
      "batch_size": 100,
      "start_time": "latest"
    },
    "rds": {
      "enabled": true,
      "instance_identifiers": ["prod-analytics", "prod-customer-db"],
      "monitor_all_instances": false,
      "poll_interval_seconds": 900,
      "config_poll_interval_seconds": 1800,
      "snapshot_poll_interval_seconds": 1800,
      "region": "us-east-1"
    },
    "cloudtrail": {
      "enabled": true,
      "s3_bucket": "company-cloudtrail-logs",
      "s3_prefix": "AWSLogs/123456789012/CloudTrail/us-east-1/",
      "event_names": [
        "CreateDBSnapshot",
        "RestoreDBInstanceFromDBSnapshot",
        "CreateDBInstanceReadReplica",
        "ModifyDBInstance"
      ],
      "poll_interval_seconds": 300,
      "lookback_time_minutes": 15
    }
  },
  "feature_mapping": {
    "tables": {
      "customers": {
        "schema": "public",
        "lattiq_columns": [
          "risk_score",
          "churn_probability",
          "fraud_indicator",
          "lifetime_value_score"
        ],
        "primary_key": ["customer_id"],
        "description": "Customer master table with LattIQ ML features"
      },
      "transactions": {
        "schema": "public",
        "lattiq_columns": ["anomaly_score", "risk_category"],
        "primary_key": ["transaction_id"],
        "description": "Transaction table with LattIQ risk features"
      }
    }
  },
  "batch_settings": {
    "max_batch_size": 100,
    "max_batch_age_sec": 30,
    "compression_level": 6,
    "max_payload_size_mb": 10
  },
  "retry_policy": {
    "max_retries": 3,
    "initial_delay_ms": 1000,
    "max_delay_ms": 30000,
    "backoff_factor": 2.0,
    "retryable_errors": [
      "TIMEOUT",
      "CONNECTION_ERROR",
      "SERVER_ERROR",
      "RATE_LIMITED"
    ]
  },
  "health_check": {
    "enabled": true,
    "report_interval_seconds": 300,
    "metric_retention_hours": 24,
    "alert_thresholds": {
      "memory_usage_mb": 512,
      "cpu_usage_percent": 80.0,
      "error_rate_percent": 5.0,
      "disk_usage_mb": 1024
    }
  },
  "logging": {
    "level": "info",
    "format": "json",
    "file": "/var/log/lattiq-agent/agent.log",
    "max_size_mb": 100,
    "max_backups": 5,
    "max_age_days": 7
  }
}
```

---

## Error Handling

### Error Classification

#### 1. Client Errors (4xx)

**Validation Errors (422)**

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      {
        "field": "data.events[0].table_access[0].lattiq_cols",
        "error": "lattiq_cols cannot be empty when is_lattiq is true",
        "code": "INVALID_LATTIQ_MAPPING"
      },
      {
        "field": "timestamp",
        "error": "timestamp cannot be in the future",
        "code": "INVALID_TIMESTAMP"
      }
    ]
  }
}
```

**Authentication Errors (401)**

```json
{
  "success": false,
  "error": {
    "code": "AUTHENTICATION_FAILED",
    "message": "Invalid API key or signature",
    "details": [
      {
        "field": "signature",
        "error": "HMAC signature verification failed",
        "code": "INVALID_SIGNATURE"
      }
    ]
  }
}
```

**Rate Limiting (429)**

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMITED",
    "message": "Request rate limit exceeded",
    "details": [
      {
        "field": "rate_limit",
        "error": "Maximum 1000 requests per minute exceeded",
        "code": "RATE_LIMIT_EXCEEDED"
      }
    ]
  },
  "retry_after": 60
}
```

#### 2. Server Errors (5xx)

**Service Unavailable (503)**

```json
{
  "success": false,
  "error": {
    "code": "SERVICE_UNAVAILABLE",
    "message": "Monitoring service temporarily unavailable",
    "details": []
  },
  "retry_after": 300
}
```

### Agent Error Handling Strategy

#### Retry Logic

```go
type RetryConfig struct {
    MaxRetries    int     `json:"max_retries"`     // Maximum retry attempts
    BaseDelay     int     `json:"base_delay_ms"`   // Initial delay
    MaxDelay      int     `json:"max_delay_ms"`    // Maximum delay
    BackoffFactor float64 `json:"backoff_factor"`  // Exponential backoff multiplier
}

// Exponential backoff calculation
func calculateDelay(attempt int, config RetryConfig) time.Duration {
    delay := float64(config.BaseDelay) * math.Pow(config.BackoffFactor, float64(attempt))
    if delay > float64(config.MaxDelay) {
        delay = float64(config.MaxDelay)
    }
    return time.Duration(delay) * time.Millisecond
}
```

#### Error Categories and Actions

| Error Type             | Action             | Retry Strategy               |
| ---------------------- | ------------------ | ---------------------------- |
| Network timeout        | Retry              | Exponential backoff          |
| Rate limiting          | Retry with delay   | Honor retry_after header     |
| Authentication failure | Log and alert      | No retry until config update |
| Validation error       | Log and skip batch | No retry for same data       |
| Server error (5xx)     | Retry              | Exponential backoff          |
| Payload too large      | Split batch        | Reduce batch size            |
| Duplicate message      | Skip               | No retry                     |

#### Dead Letter Queue

```go
type DeadLetterEvent struct {
    OriginalMessage  MonitoringMessage `json:"original_message"`
    ErrorHistory     []ErrorAttempt    `json:"error_history"`
    FirstFailed      int64             `json:"first_failed"`
    LastAttempt      int64             `json:"last_attempt"`
    TotalAttempts    int               `json:"total_attempts"`
    FinalError       string            `json:"final_error"`
}

type ErrorAttempt struct {
    Timestamp   int64  `json:"timestamp"`
    ErrorCode   string `json:"error_code"`
    ErrorMsg    string `json:"error_message"`
    StatusCode  int    `json:"status_code"`
    RetryAfter  int    `json:"retry_after,omitempty"`
}
```

---

## Performance Requirements

### Latency Requirements

| Component             | Requirement  | Measurement                    |
| --------------------- | ------------ | ------------------------------ |
| Query log processing  | < 2 minutes  | From log entry to transmission |
| RDS API polling       | < 5 minutes  | From API call to transmission  |
| CloudTrail processing | < 5 minutes  | From event to transmission     |
| HTTP API response     | < 1 second   | 95th percentile                |
| Batch processing      | < 30 seconds | End-to-end batch processing    |

### Throughput Requirements

| Metric                 | Requirement   | Peak Capacity  |
| ---------------------- | ------------- | -------------- |
| Query events/second    | 1,000         | 5,000          |
| Batch requests/minute  | 100           | 500            |
| Concurrent connections | 50 per client | 200 per client |
| Data payload size      | 10 MB typical | 50 MB maximum  |

### Resource Requirements

#### Agent Resource Limits

```go
type ResourceLimits struct {
    MaxMemoryMB     int     `json:"max_memory_mb"`      // 512 MB default
    MaxCPUPercent   float64 `json:"max_cpu_percent"`    // 10% default
    MaxDiskMB       int     `json:"max_disk_mb"`        // 1 GB default
    MaxConnections  int     `json:"max_connections"`    // 10 default
    MaxBatchQueue   int     `json:"max_batch_queue"`    // 100 batches default
}
```

#### Service Level Objectives (SLOs)

**Availability**: 99.9% uptime (excluding maintenance windows)
**Reliability**: 99.99% data delivery success rate
**Durability**: 99.999% data retention (no data loss)
**Scalability**: Linear scaling to 1000+ concurrent clients

### Monitoring and Alerting

#### Agent Metrics

```go
type AgentMetrics struct {
    // Collection Metrics
    EventsCollected    map[string]int64  `json:"events_collected"`     // by source
    EventsProcessed    map[string]int64  `json:"events_processed"`     // by source
    EventsTransmitted  map[string]int64  `json:"events_transmitted"`   // by source
    EventsFailed       map[string]int64  `json:"events_failed"`        // by source

    // Performance Metrics
    AvgProcessingTime  map[string]float64 `json:"avg_processing_time"`  // by source (ms)
    AvgTransmissionTime float64           `json:"avg_transmission_time"` // API calls (ms)
    BatchUtilization   float64            `json:"batch_utilization"`     // % of max batch size

    // Error Metrics
    ErrorRate          map[string]float64 `json:"error_rate"`           // by source (%)
    RetryRate          float64            `json:"retry_rate"`           // % of requests retried
    DeadLetterCount    int64              `json:"dead_letter_count"`    // Failed permanently

    // Resource Metrics
    MemoryUsageMB      int64              `json:"memory_usage_mb"`
    CPUUsagePercent    float64            `json:"cpu_usage_percent"`
    DiskUsageMB        int64              `json:"disk_usage_mb"`
    NetworkBytesOut    int64              `json:"network_bytes_out"`
}
```

#### Service Metrics

```go
type ServiceMetrics struct {
    // Ingestion Metrics
    RequestsPerSecond   float64 `json:"requests_per_second"`
    EventsPerSecond     float64 `json:"events_per_second"`
    ProcessingLatencyP95 float64 `json:"processing_latency_p95_ms"`

    // Client Metrics
    ActiveClients       int     `json:"active_clients"`
    ClientErrorRate     float64 `json:"client_error_rate"`
    ClientHealthy       int     `json:"clients_healthy"`
    ClientDegraded      int     `json:"clients_degraded"`

    // System Metrics
    QueueDepth          int64   `json:"queue_depth"`
    ProcessorUtilization float64 `json:"processor_utilization"`
    StorageUtilization  float64 `json:"storage_utilization"`
}
```

---

## Security Considerations

### Data Protection

#### In Transit

- **TLS 1.3**: All HTTP communications encrypted
- **Certificate Pinning**: Agent validates service certificates
- **Perfect Forward Secrecy**: Session keys not derivable from long-term keys

#### At Rest

- **Encryption**: Optional AES-256-GCM for sensitive payloads
- **Key Management**: Rotating API keys with automatic refresh
- **Audit Logging**: All API calls logged with full context

#### Data Minimization

- **Query Patterns**: Only parameterized queries transmitted, not raw SQL
- **Hash-based Deduplication**: Sensitive data hashed for privacy
- **Selective Collection**: Only LattIQ-relevant data collected

### Access Control

#### Authentication

```go
type AuthenticationFlow struct {
    Step1 string `json:"step_1"` // "Generate JWT with client credentials"
    Step2 string `json:"step_2"` // "Calculate HMAC signature of payload"
    Step3 string `json:"step_3"` // "Send request with auth headers"
    Step4 string `json:"step_4"` // "Service validates signature and timestamp"
}
```

#### Authorization

- **Client Isolation**: Each client can only access their own data
- **Resource Scoping**: API keys scoped to specific data sources
- **Role-based Access**: Different permission levels for different operations

### Compliance

#### Data Governance

- **Retention Policies**: Configurable data retention periods
- **Right to Delete**: Support for data deletion requests
- **Audit Trails**: Complete audit logging for compliance reporting

#### Privacy Protection

- **Data Anonymization**: Personal data stripped from monitoring data
- **Consent Management**: Respect client data processing agreements
- **Cross-border Compliance**: Regional data residency requirements

---

## Versioning and Compatibility

### API Versioning Strategy

#### Semantic Versioning

- **Major Version**: Breaking changes to message format or API
- **Minor Version**: Backward-compatible feature additions
- **Patch Version**: Bug fixes and non-breaking improvements

#### Backward Compatibility

```go
type VersionCompatibility struct {
    CurrentVersion    string   `json:"current_version"`     // "1.0"
    SupportedVersions []string `json:"supported_versions"`  // ["1.0", "0.9"]
    DeprecatedVersions []string `json:"deprecated_versions"` // ["0.8"]
    MinimumVersion    string   `json:"minimum_version"`     // "0.9"
}
```

#### Migration Strategy

- **Gradual Rollout**: New versions deployed gradually
- **Dual Operation**: Old and new versions run simultaneously during transition
- **Feature Flags**: New features gated by version compatibility
- **Deprecation Notice**: 90-day advance notice for breaking changes

### Message Format Evolution

#### Extensible Design

- **Optional Fields**: New fields added as optional to maintain compatibility
- **Polymorphic Data**: `data` field accepts different structures based on `message_type`
- **Metadata Expansion**: Additional context can be added to `metadata` field

#### Schema Validation

```go
type SchemaValidator struct {
    Version    string                 `json:"version"`
    Schema     map[string]interface{} `json:"schema"`     // JSON Schema
    Required   []string               `json:"required"`   // Required fields
    Optional   []string               `json:"optional"`   // Optional fields
    Deprecated []string               `json:"deprecated"` // Deprecated fields
}
```

---

## Implementation Guidelines

### Agent Implementation

#### Go Implementation Structure

```go
// Package structure
package main

import (
    "github.com/lattiq/monitoring-agent/internal/collector"
    "github.com/lattiq/monitoring-agent/internal/processor"
    "github.com/lattiq/monitoring-agent/internal/transmitter"
    "github.com/lattiq/monitoring-agent/internal/config"
    "github.com/lattiq/monitoring-agent/internal/health"
)

type Agent struct {
    config      *config.Config
    collectors  map[string]collector.Collector
    processor   *processor.EventProcessor
    transmitter *transmitter.HTTPTransmitter
    health      *health.Monitor
}

func (a *Agent) Start() error {
    // Initialize collectors
    // Start background goroutines
    // Begin health monitoring
    // Start metrics collection
}
```

#### Key Interfaces

```go
type Collector interface {
    Name() string
    Collect(ctx context.Context) ([]Event, error)
    Health() CollectorHealth
}

type Processor interface {
    Process(events []Event) ([]MonitoringMessage, error)
    Validate(message MonitoringMessage) error
}

type Transmitter interface {
    Send(ctx context.Context, message MonitoringMessage) error
    SendBatch(ctx context.Context, batch []MonitoringMessage) error
    Health() TransmitterHealth
}
```

### Service Implementation

#### Microservices Architecture

```go
// Service components
type MonitoringService struct {
    Ingestion   *IngestionService   // Receive and validate data
    Processing  *ProcessingService  // Analyze and detect patterns
    Storage     *StorageService     // Persist data and metadata
    Alerting    *AlertingService    // Generate and send alerts
    API         *APIService         // HTTP API endpoints
}
```

#### Database Schema (High-level)

```sql
-- Client management
CREATE TABLE clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    config_hash VARCHAR(64),
    status VARCHAR(50) DEFAULT 'active'
);

-- Event storage (time-series optimized)
CREATE TABLE query_events (
    event_id UUID PRIMARY KEY,
    client_id VARCHAR(255) REFERENCES clients(client_id),
    timestamp TIMESTAMP NOT NULL,
    database_name VARCHAR(255),
    user_name VARCHAR(255),
    query_hash VARCHAR(64),
    query_pattern TEXT,
    table_access JSONB,
    is_lattiq_access BOOLEAN,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Partitioned by timestamp for performance
CREATE INDEX idx_query_events_client_timestamp
ON query_events(client_id, timestamp);

CREATE INDEX idx_query_events_lattiq_access
ON query_events(client_id, timestamp)
WHERE is_lattiq_access = true;
```

---

## Testing Strategy

### Unit Testing

#### Agent Tests

```go
func TestQueryLogParser(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected QueryLogEvent
        wantErr  bool
    }{
        {
            name: "SELECT with LattIQ columns",
            input: `2025-01-15 12:00:00 UTC:192.168.1.100:app_user@production:[12345]:LOG: statement: SELECT customer_id, risk_score FROM customers WHERE customer_id = 1`,
            expected: QueryLogEvent{
                DatabaseName: "production",
                UserName:     "app_user",
                QueryType:    "SELECT",
                TableAccess: []TableAccess{
                    {
                        Schema:     "public",
                        Table:      "customers",
                        Columns:    []string{"customer_id", "risk_score"},
                        AccessType: "SELECT",
                        IsLattIQ:   true,
                        LattIQCols: []string{"risk_score"},
                    },
                },
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            parser := NewQueryLogParser(testConfig)
            result, err := parser.Parse(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

### Integration Testing

#### End-to-End Test Flow

```go
func TestEndToEndDataFlow(t *testing.T) {
    // Setup test environment
    testDB := setupTestDatabase(t)
    testService := setupTestService(t)
    agent := setupTestAgent(t, testDB, testService)

    // Execute test query in database
    _, err := testDB.Exec("SELECT customer_id, risk_score FROM customers WHERE customer_id = 1")
    require.NoError(t, err)

    // Wait for agent to collect and transmit
    time.Sleep(5 * time.Second)

    // Verify data received by service
    events := testService.GetReceivedEvents()
    require.Len(t, events, 1)

    event := events[0]
    assert.Equal(t, "SELECT", event.QueryType)
    assert.True(t, event.TableAccess[0].IsLattIQ)
    assert.Contains(t, event.TableAccess[0].LattIQCols, "risk_score")
}
```

### Load Testing

#### Performance Benchmarks

```go
func BenchmarkQueryProcessing(b *testing.B) {
    processor := NewEventProcessor(testConfig)
    sampleQuery := generateSampleQueryLog()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := processor.Process(sampleQuery)
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkBatchTransmission(b *testing.B) {
    transmitter := NewHTTPTransmitter(testConfig)
    batch := generateSampleBatch(100) // 100 events

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        err := transmitter.SendBatch(context.Background(), batch)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

---

## Deployment Guide

### Agent Deployment

#### Docker Deployment

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o lattiq-agent ./cmd/agent

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/lattiq-agent .
COPY --from=builder /app/config/agent.yaml .
CMD ["./lattiq-agent", "--config", "agent.yaml"]
```

#### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lattiq-monitoring-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: lattiq-agent
  template:
    metadata:
      labels:
        app: lattiq-agent
    spec:
      containers:
        - name: lattiq-agent
          image: lattiq/monitoring-agent:1.0.0
          env:
            - name: CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: lattiq-credentials
                  key: client-id
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: lattiq-credentials
                  key: api-key
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "200m"
          volumeMounts:
            - name: config
              mountPath: /app/config
            - name: logs
              mountPath: /var/log/lattiq-agent
      volumes:
        - name: config
          configMap:
            name: lattiq-agent-config
        - name: logs
          emptyDir: {}
```

#### AWS IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents",
        "logs:FilterLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/rds/instance/*/postgresql"
    },
    {
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBParameters",
        "rds:DescribeDBParameterGroups"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::your-cloudtrail-bucket/*"
    }
  ]
}
```

### Service Deployment

#### Infrastructure Requirements

- **Load Balancer**: ALB with SSL termination
- **Auto Scaling**: Container-based scaling (2-20 instances)
- **Database**: PostgreSQL with read replicas
- **Cache**: Redis for real-time analytics
- **Monitoring**: CloudWatch, Prometheus, Grafana

---

## Support and Maintenance

### Operational Procedures

#### Agent Health Monitoring

```go
type HealthCheck struct {
    ComponentStatus map[string]string `json:"component_status"`
    LastHeartbeat   int64             `json:"last_heartbeat"`
    Version         string            `json:"version"`
    Uptime          int64             `json:"uptime_seconds"`
    Errors          []string          `json:"recent_errors"`
}

func (a *Agent) HealthCheck() HealthCheck {
    return HealthCheck{
        ComponentStatus: map[string]string{
            "collector.query_logs":  a.collectors["query_logs"].Status(),
            "collector.rds":         a.collectors["rds"].Status(),
            "collector.cloudtrail":  a.collectors["cloudtrail"].Status(),
            "transmitter":           a.transmitter.Status(),
        },
        LastHeartbeat: time.Now().Unix(),
        Version:       a.version,
        Uptime:        time.Since(a.startTime).Seconds(),
        Errors:        a.getRecentErrors(),
    }
}
```

#### Troubleshooting Guide

**Common Issues and Resolutions:**

1. **Agent Not Collecting Data**

   - Check CloudWatch log group permissions
   - Verify RDS parameter groups allow query logging
   - Confirm network connectivity to AWS APIs

2. **High Memory Usage**

   - Reduce batch sizes in configuration
   - Increase transmission frequency
   - Check for memory leaks in SQL parsing

3. **Authentication Failures**

   - Verify API keys are current
   - Check system clock synchronization
   - Validate HMAC signature calculation

4. **Missing Query Events**
   - Confirm PostgreSQL `log_statement = 'all'` setting
   - Check CloudWatch log retention settings
   - Verify filter patterns are not too restrictive

### Upgrade Procedures

#### Agent Upgrade Process

1. **Preparation**: Backup current configuration
2. **Testing**: Deploy to staging environment
3. **Validation**: Verify data collection continues
4. **Production**: Rolling deployment with health checks
5. **Verification**: Confirm all metrics are normal

#### Configuration Updates

```go
type ConfigUpdate struct {
    Version     string                 `json:"version"`
    Changes     []ConfigChange         `json:"changes"`
    Rollback    bool                   `json:"rollback_available"`
    ApplyTime   int64                  `json:"apply_time"`
    Metadata    map[string]interface{} `json:"metadata"`
}

type ConfigChange struct {
    Path     string `json:"path"`      // "data_sources.query_logs.batch_size"
    OldValue string `json:"old_value"`
    NewValue string `json:"new_value"`
    Action   string `json:"action"`    // "add", "modify", "delete"
}
```

---

## Conclusion

This contract specification provides a comprehensive foundation for the Data Abuse Monitoring System, ensuring:

- **Scalability**: Support for multiple clients with varying feature sets
- **Reliability**: Robust error handling and retry mechanisms
- **Security**: Strong authentication and data protection
- **Maintainability**: Clean interfaces and extensible design
- **Performance**: Efficient data collection and transmission
- **Compliance**: Complete audit trails and data governance

The contract serves as the definitive specification for both agent and service implementations, enabling independent development while ensuring seamless integration.

For questions or clarifications, contact the LattIQ Engineering Team at engineering@lattiq.com.

---

**Document End**
