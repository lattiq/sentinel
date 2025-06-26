package types

import "time"

// MonitoringMessage represents the base message structure as per contract
type MonitoringMessage struct {
	MessageID   string                 `json:"message_id"`
	ClientID    string                 `json:"client_id"`
	Timestamp   int64                  `json:"timestamp"`
	MessageType string                 `json:"message_type"`
	BatchSize   int                    `json:"batch_size"`
	Data        interface{}            `json:"data"`
	Metadata    map[string]interface{} `json:"metadata"`
	Version     string                 `json:"version"`
}

// MessageTypes defines the supported message types
const (
	MessageTypeQueryLogs    = "query_logs"
	MessageTypeRDSInstances = "rds_instances"
	MessageTypeRDSConfig    = "rds_config"
	MessageTypeRDSSnapshots = "rds_snapshots"
	MessageTypeCloudTrail   = "cloudtrail"
	MessageTypeHealth       = "health"
	MessageTypeAgentHealth  = "agent_health"
	MessageTypeConfig       = "config"
)

// QueryLogEvent represents a PostgreSQL query log event
type QueryLogEvent struct {
	// Basic Query Information
	Timestamp       int64  `json:"timestamp"`
	DatabaseName    string `json:"database_name"`
	UserName        string `json:"user_name"`
	ApplicationName string `json:"application_name"`

	// Query Analysis
	QueryHash    string  `json:"query_hash"`
	QueryPattern string  `json:"query_pattern"`
	RawQuery     string  `json:"raw_query,omitempty"` // Raw SQL query for pattern analysis
	Duration     float64 `json:"duration_ms"`
	ConnectionID string  `json:"connection_id"`
	QueryType    string  `json:"query_type"`
	RowsAffected *int64  `json:"rows_affected,omitempty"`

	// LattIQ-Specific Analysis
	TableAccess []TableAccess `json:"table_access"`

	// Replication Detection
	IsReplication bool           `json:"is_replication"`
	ReplicationOp *ReplicationOp `json:"replication_op,omitempty"`

	// Additional Context
	ClientIP  string `json:"client_ip,omitempty"`
	SSLUsed   bool   `json:"ssl_used"`
	QuerySize int    `json:"query_size_bytes"`
}

// TableAccess represents table and column access information
type TableAccess struct {
	Schema      string   `json:"schema"`
	Table       string   `json:"table"`
	Columns     []string `json:"columns"`
	AccessType  string   `json:"access_type"`
	IsLattIQ    bool     `json:"is_lattiq"`
	LattIQCols  []string `json:"lattiq_cols"`
	RowEstimate *int64   `json:"row_estimate,omitempty"`
}

// ReplicationOp represents replication operation details
type ReplicationOp struct {
	Command      string            `json:"command"`
	ObjectName   string            `json:"object_name"`
	TargetTables []string          `json:"target_tables,omitempty"`
	SlotName     string            `json:"slot_name,omitempty"`
	Options      map[string]string `json:"options,omitempty"`
}

// RDSInstanceEvent represents RDS instance information
type RDSInstanceEvent struct {
	InstanceID                 string   `json:"instance_id"`
	InstanceClass              string   `json:"instance_class"`
	Engine                     string   `json:"engine"`
	EngineVersion              string   `json:"engine_version"`
	Status                     string   `json:"status"`
	LastModified               int64    `json:"last_modified"`
	ReadReplicaSource          *string  `json:"read_replica_source,omitempty"`
	ReadReplicas               []string `json:"read_replicas"`
	RestoreTime                *int64   `json:"restore_time,omitempty"`
	BackupRetentionPeriod      int      `json:"backup_retention_period"`
	PreferredBackupWindow      string   `json:"preferred_backup_window"`
	PreferredMaintenanceWindow string   `json:"preferred_maintenance_window"`
	MultiAZ                    bool     `json:"multi_az"`
	AvailabilityZone           string   `json:"availability_zone"`
	AllocatedStorage           int      `json:"allocated_storage"`
	StorageType                string   `json:"storage_type"`
	StorageEncrypted           bool     `json:"storage_encrypted"`
	VpcId                      string   `json:"vpc_id"`
	SubnetGroup                string   `json:"subnet_group"`
	PubliclyAccessible         bool     `json:"publicly_accessible"`
}

// RDSConfigEvent represents RDS configuration changes
type RDSConfigEvent struct {
	InstanceID       string            `json:"instance_id"`
	ParameterGroup   string            `json:"parameter_group"`
	Parameters       []ConfigParameter `json:"parameters"`
	ParameterChanges []ParameterChange `json:"parameter_changes"`
	LastModified     int64             `json:"last_modified"`
	ApplyMethod      string            `json:"apply_method"`
}

// ParameterChange represents a configuration parameter change
type ParameterChange struct {
	Name        string `json:"name"`
	OldValue    string `json:"old_value"`
	NewValue    string `json:"new_value"`
	Description string `json:"description"`
}

// ConfigParameter represents a single RDS parameter
type ConfigParameter struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	DefaultValue  string `json:"default_value"`
	IsModifiable  bool   `json:"is_modifiable"`
	IsReplication bool   `json:"is_replication"`
	IsBackup      bool   `json:"is_backup"`
	ApplyType     string `json:"apply_type"`
	DataType      string `json:"data_type"`
}

// RDSSnapshotEvent represents RDS snapshot information
type RDSSnapshotEvent struct {
	SnapshotID       string `json:"snapshot_id"`
	InstanceID       string `json:"instance_id"`
	SnapshotType     string `json:"snapshot_type"`
	CreateTime       int64  `json:"create_time"`
	DatabaseTime     int64  `json:"database_time"`
	Status           string `json:"status"`
	AllocatedStorage int    `json:"allocated_storage"`
	Encrypted        bool   `json:"encrypted"`
	KmsKeyId         string `json:"kms_key_id,omitempty"`
	Engine           string `json:"engine"`
	EngineVersion    string `json:"engine_version"`
	LicenseModel     string `json:"license_model"`
	Port             int    `json:"port"`
}

// CloudTrailEvent represents AWS CloudTrail events
type CloudTrailEvent struct {
	EventID          string                 `json:"event_id"`
	EventName        string                 `json:"event_name"`
	EventTime        int64                  `json:"event_time"`
	EventSource      string                 `json:"event_source"`
	EventVersion     string                 `json:"event_version"`
	AWSRegion        string                 `json:"aws_region"`
	SourceIP         string                 `json:"source_ip"`
	UserAgent        string                 `json:"user_agent"`
	UserIdentity     UserIdentity           `json:"user_identity"`
	RequestParams    map[string]interface{} `json:"request_parameters"`
	ResponseElements map[string]interface{} `json:"response_elements"`
	ReadOnly         bool                   `json:"read_only"`
	ResourceName     string                 `json:"resource_name,omitempty"`
	ErrorCode        string                 `json:"error_code,omitempty"`
	ErrorMessage     string                 `json:"error_message,omitempty"`
}

// UserIdentity represents CloudTrail user identity
type UserIdentity struct {
	Type           string          `json:"type"`
	PrincipalId    string          `json:"principal_id"`
	UserName       string          `json:"user_name"`
	ARN            string          `json:"arn"`
	AccountId      string          `json:"account_id"`
	AccessKeyId    string          `json:"access_key_id,omitempty"`
	SessionContext *SessionContext `json:"session_context,omitempty"`
}

// SessionContext represents session information
type SessionContext struct {
	SessionIssuer    SessionIssuer `json:"session_issuer"`
	CreationDate     int64         `json:"creation_date"`
	MFAAuthenticated bool          `json:"mfa_authenticated"`
}

// SessionIssuer represents session issuer information
type SessionIssuer struct {
	Type        string `json:"type"`
	PrincipalId string `json:"principal_id"`
	ARN         string `json:"arn"`
	UserName    string `json:"user_name"`
}

// AgentHealthEvent represents agent health information
type AgentHealthEvent struct {
	AgentVersion    string                 `json:"agent_version"`
	Status          string                 `json:"status"`
	UptimeSeconds   int64                  `json:"uptime_seconds"`
	CollectorStates map[string]string      `json:"collector_states"`
	SystemMetrics   SystemMetrics          `json:"system_metrics"`
	ErrorCount      int64                  `json:"error_count"`
	Timestamp       int64                  `json:"timestamp"`
	ConfigHash      string                 `json:"config_hash,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ConfigEvent represents configuration information and changes
type ConfigEvent struct {
	ClientID        string                 `json:"client_id"`
	ClientName      string                 `json:"client_name"`
	Environment     string                 `json:"environment"`
	ConfigVersion   string                 `json:"config_version"`
	ConfigHash      string                 `json:"config_hash"`
	PreviousHash    string                 `json:"previous_hash,omitempty"`
	ChangedSections []string               `json:"changed_sections,omitempty"`
	Configuration   interface{}            `json:"configuration"`
	Timestamp       int64                  `json:"timestamp"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// HealthEvent represents general system health information
type HealthEvent struct {
	ComponentName string                 `json:"component_name"`
	Status        string                 `json:"status"`
	Timestamp     int64                  `json:"timestamp"`
	UptimeSeconds int64                  `json:"uptime_seconds"`
	ErrorCount    int64                  `json:"error_count"`
	LastError     string                 `json:"last_error,omitempty"`
	Metrics       map[string]interface{} `json:"metrics,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// BatchMetrics represents batching performance metrics
type BatchMetrics struct {
	TotalBatches     int64   `json:"total_batches"`
	AvgBatchSize     float64 `json:"avg_batch_size"`
	AvgBatchAge      float64 `json:"avg_batch_age_ms"`
	CompressionRatio float64 `json:"compression_ratio"`
}

// APIMetrics represents API call performance metrics
type APIMetrics struct {
	TotalRequests   int64   `json:"total_requests"`
	SuccessRate     float64 `json:"success_rate"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	RetryRate       float64 `json:"retry_rate"`
}

// HealthIssue represents a health issue
type HealthIssue struct {
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	Count     int    `json:"count"`
}

// Event represents a generic event that can be processed
type Event struct {
	ID          string            `json:"id"`
	Type        EventType         `json:"type"`
	Timestamp   time.Time         `json:"timestamp"`
	Source      string            `json:"source"`
	Data        interface{}       `json:"data"`
	QueryLog    *QueryLogEvent    `json:"query_log,omitempty"`
	RDSInstance *RDSInstanceEvent `json:"rds_instance,omitempty"`
	RDSConfig   *RDSConfigEvent   `json:"rds_config,omitempty"`
	RDSSnapshot *RDSSnapshotEvent `json:"rds_snapshot,omitempty"`
	CloudTrail  *CloudTrailEvent  `json:"cloudtrail,omitempty"`
	Health      *HealthEvent      `json:"health,omitempty"`
	AgentHealth *AgentHealthEvent `json:"agent_health,omitempty"`
	Config      *ConfigEvent      `json:"config,omitempty"`
}

// QueryLogAnalysis represents the analysis results for a query log event
type QueryLogAnalysis struct {
	FeatureAccess     []FeatureAccess `json:"feature_access"`
	SuspiciousPattern []string        `json:"suspicious_patterns"`
	RiskScore         float64         `json:"risk_score"`
	Anomalies         []string        `json:"anomalies"`
}

// FeatureAccess represents access to LattIQ feature columns
type FeatureAccess struct {
	TableName  string   `json:"table_name"`
	Columns    []string `json:"columns"`
	AccessType string   `json:"access_type"`
}

// BatchPayload represents a batch of monitoring messages for transmission
type BatchPayload struct {
	ClientID  string                 `json:"client_id"`
	Timestamp int64                  `json:"timestamp"`
	BatchSize int                    `json:"batch_size"`
	Messages  []MonitoringMessage    `json:"messages"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// TransmissionMetrics represents transmission performance metrics
type TransmissionMetrics struct {
	TotalRequests    int64         `json:"total_requests"`
	SuccessfulSends  int64         `json:"successful_sends"`
	FailedSends      int64         `json:"failed_sends"`
	RetriedRequests  int64         `json:"retried_requests"`
	SuccessRate      float64       `json:"success_rate"`
	AvgResponseTime  time.Duration `json:"avg_response_time"`
	LastTransmitTime time.Time     `json:"last_transmit_time"`
}

// HealthData represents agent health metrics
type HealthData struct {
	LastUpdate  time.Time         `json:"last_update"`
	Status      string            `json:"status"`
	ErrorCount  int64             `json:"error_count"`
	UptimeStart time.Time         `json:"uptime_start"`
	Collectors  map[string]string `json:"collectors"`
	SystemInfo  SystemMetrics     `json:"system_info"`
}

// SystemMetrics represents system-level metrics
type SystemMetrics struct {
	MemoryUsageMB  int     `json:"memory_usage_mb"`
	CPUPercent     float64 `json:"cpu_percent"`
	DiskUsageMB    int     `json:"disk_usage_mb"`
	GoroutineCount int     `json:"goroutine_count"`
}

// MetricsProvider interface for components that provide metrics
type MetricsProvider interface {
	GetMetrics() map[string]interface{}
}
