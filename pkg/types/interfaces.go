package types

import (
	"context"
	"time"
)

// Collector defines the interface for data collectors
type Collector interface {
	// Name returns the collector name
	Name() string

	// Start begins data collection
	Start(ctx context.Context) error

	// Stop gracefully stops the collector
	Stop(ctx context.Context) error

	// Collect performs a single collection cycle
	Collect(ctx context.Context) ([]Event, error)

	// Health returns the current health status
	Health() CollectorHealth

	// Subscribe returns a channel for real-time events
	Subscribe() <-chan Event
}

// Processor defines the interface for event processing
type Processor interface {
	// Process processes a batch of events
	Process(ctx context.Context, events []Event) ([]MonitoringMessage, error)

	// Validate validates a monitoring message
	Validate(message MonitoringMessage) error
}

// Transmitter defines the interface for data transmission
type Transmitter interface {
	// Send transmits a single monitoring message
	Send(ctx context.Context, message MonitoringMessage) error

	// SendBatch transmits a batch of monitoring messages
	SendBatch(ctx context.Context, messages []MonitoringMessage) error

	// Health returns the current health status
	Health() TransmitterHealth
}

// HealthMonitor defines the interface for health monitoring
type HealthMonitor interface {
	// Start begins health monitoring
	Start(ctx context.Context) error

	// Stop stops health monitoring
	Stop(ctx context.Context) error

	// GetHealth returns current health status
	GetHealth() AgentHealthEvent

	// RecordMetric records a metric
	RecordMetric(name string, value float64, tags map[string]string)

	// RecordError records an error
	RecordError(component string, err error)
}

// CollectorHealth represents collector health status
type CollectorHealth struct {
	Status          string           `json:"status"` // healthy, degraded, error
	LastCollection  time.Time        `json:"last_collection"`
	EventsCollected int64            `json:"events_collected"`
	ErrorsCount     int64            `json:"errors_count"`
	LastError       string           `json:"last_error,omitempty"`
	Performance     PerformanceStats `json:"performance"`
}

// TransmitterHealth represents transmitter health status
type TransmitterHealth struct {
	Status           string           `json:"status"` // healthy, degraded, error
	LastTransmission time.Time        `json:"last_transmission"`
	MessagesSent     int64            `json:"messages_sent"`
	ErrorsCount      int64            `json:"errors_count"`
	LastError        string           `json:"last_error,omitempty"`
	Performance      PerformanceStats `json:"performance"`
}

// PerformanceStats represents performance statistics
type PerformanceStats struct {
	AvgLatency  time.Duration `json:"avg_latency"`
	SuccessRate float64       `json:"success_rate"`
	Throughput  float64       `json:"throughput"` // events per second
	LastUpdated time.Time     `json:"last_updated"`
}

// CollectorType defines collector types
type CollectorType string

const (
	CollectorTypeQueryLogs  CollectorType = "query_logs"
	CollectorTypeRDS        CollectorType = "rds"
	CollectorTypeCloudTrail CollectorType = "cloudtrail"
)

// EventType defines event types
type EventType string

const (
	EventTypeQueryLog    EventType = "query_log"
	EventTypeRDSInstance EventType = "rds_instance"
	EventTypeRDSCluster  EventType = "rds_cluster"
	EventTypeRDSConfig   EventType = "rds_config"
	EventTypeRDSSnapshot EventType = "rds_snapshot"
	EventTypeCloudTrail  EventType = "cloudtrail"
	EventTypeHealth      EventType = "health"
	EventTypeAgentHealth EventType = "agent_health"
	EventTypeConfig      EventType = "config"
)

// HealthStatus defines health status values
type HealthStatus string

const (
	HealthStatusHealthy  HealthStatus = "healthy"
	HealthStatusDegraded HealthStatus = "degraded"
	HealthStatusError    HealthStatus = "error"
	HealthStatusStopped  HealthStatus = "stopped"
)

// ErrorType defines error categories
type ErrorType string

const (
	ErrorTypeConnection  ErrorType = "connection"
	ErrorTypePermission  ErrorType = "permission"
	ErrorTypeValidation  ErrorType = "validation"
	ErrorTypeResource    ErrorType = "resource"
	ErrorTypeTimeout     ErrorType = "timeout"
	ErrorTypeRateLimit   ErrorType = "rate_limit"
	ErrorTypeServerError ErrorType = "server_error"
)

// ComponentError represents a structured error with context
type ComponentError struct {
	Type      ErrorType              `json:"type"`
	Component string                 `json:"component"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Cause     error                  `json:"-"`
}

// Error implements the error interface
func (e ComponentError) Error() string {
	return e.Message
}

// Unwrap returns the underlying error
func (e ComponentError) Unwrap() error {
	return e.Cause
}
