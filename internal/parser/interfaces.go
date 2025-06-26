package parser

import (
	"time"

	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

// LogParser defines the interface for log parsing implementations
type LogParser interface {
	// ParseLogMessage parses a raw log message into a structured QueryLogEvent
	ParseLogMessage(rawMessage string, logStream string, timestamp time.Time) (*sentinelTypes.QueryLogEvent, error)

	// AnalyzeForAbuse performs abuse analysis on the parsed event
	AnalyzeForAbuse(event *sentinelTypes.QueryLogEvent) *sentinelTypes.QueryLogAnalysis
}

// Ensure our parsers implement the interface
var _ LogParser = (*PostgreSQLParser)(nil)
