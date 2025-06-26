package parser

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/lattiq/sentinel/internal/config"
)

// LogFormatParser handles dynamic PostgreSQL log format parsing
type LogFormatParser struct {
	config   *config.LogFormatConfig
	regexes  map[string]*regexp.Regexp
	patterns map[string]string
}

// PostgreSQL log_line_prefix escape sequences and their meanings
var pgLogEscapeSequences = map[string]string{
	"%a": "application_name",       // Application name
	"%u": "user_name",              // User name
	"%d": "database_name",          // Database name
	"%r": "remote_host",            // Remote host name or IP address, and remote port
	"%h": "remote_host_only",       // Remote host name or IP address only
	"%p": "process_id",             // Process ID
	"%t": "timestamp",              // Timestamp without milliseconds
	"%m": "timestamp_ms",           // Timestamp with milliseconds
	"%n": "timestamp_unix",         // Timestamp as seconds since epoch
	"%i": "command_tag",            // Command tag: type of session's current command
	"%e": "sql_state",              // SQLSTATE error code
	"%c": "session_id",             // Session ID
	"%l": "session_line_num",       // Session line number for each process
	"%s": "session_start",          // Process start timestamp
	"%v": "virtual_transaction_id", // Virtual transaction ID
	"%x": "transaction_id",         // Transaction ID (0 if none)
	"%q": "query_id",               // Query ID (0 if none)
	"%%": "literal_percent",        // Literal %
}

// NewLogFormatParser creates a new dynamic log format parser
func NewLogFormatParser(config *config.LogFormatConfig) (*LogFormatParser, error) {
	parser := &LogFormatParser{
		config:   config,
		regexes:  make(map[string]*regexp.Regexp),
		patterns: make(map[string]string),
	}

	// Handle empty log_line_prefix (no prefix configured)
	if config.LogLinePrefix == "" {
		err := parser.parseEmptyPrefix()
		if err != nil {
			return nil, fmt.Errorf("failed to setup empty prefix parser: %w", err)
		}
	} else {
		// Parse the configured log_line_prefix
		err := parser.parseLogLinePrefix(config.LogLinePrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to parse log_line_prefix: %w", err)
		}
	}

	// Add common formats if auto-detect is enabled
	if config.AutoDetect {
		parser.setupCommonFormats()
		// Also add empty prefix format for auto-detect
		if config.LogLinePrefix != "" {
			parser.parseEmptyPrefix()
		}
	}

	if len(parser.regexes) == 0 {
		return nil, fmt.Errorf("no valid regex patterns generated")
	}

	return parser, nil
}

// setupCommonFormats sets up regex patterns for common PostgreSQL log formats
func (p *LogFormatParser) setupCommonFormats() {
	commonFormats := []string{
		"%t:%r:%u@%d:[%p]:", // Standard format
		"%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h ", // Detailed format
		"%m [%p] %q%u@%d ",     // With milliseconds and query ID
		"%t:%r:%u@%d:[%p]:%e:", // With error state
		"%t [%p]: ",            // Minimal format
		"%m:%r:%u@%d:[%p]:",    // Millisecond timestamp
	}

	for _, format := range commonFormats {
		p.parseLogLinePrefix(format)
	}
}

// parseLogLinePrefix converts a PostgreSQL log_line_prefix into regex patterns
func (p *LogFormatParser) parseLogLinePrefix(logLinePrefix string) error {
	// Build regex pattern by replacing escape sequences
	regexPattern := regexp.QuoteMeta(logLinePrefix)

	// Track field positions for extraction
	fieldMap := make(map[string]int)
	groupIndex := 1

	// Replace escape sequences with capture groups
	for sequence, fieldName := range pgLogEscapeSequences {
		if strings.Contains(logLinePrefix, sequence) {
			var pattern string

			switch fieldName {
			case "timestamp", "timestamp_ms":
				// Match various timestamp formats
				pattern = `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?(?: \w+)?)`
			case "remote_host":
				// Match IP:port or hostname:port
				pattern = `([^:]+(?:\(\d+\))?)`
			case "remote_host_only":
				// Match IP or hostname only
				pattern = `([^:\s]+)`
			case "user_name", "database_name", "application_name":
				// Match alphanumeric with common special chars
				pattern = `([^@:\s]+)`
			case "process_id", "session_id", "session_line_num":
				// Match numeric values
				pattern = `(\d+)`
			case "command_tag":
				// Match SQL command tags
				pattern = `([A-Z][A-Z_]*)`
			case "sql_state":
				// Match 5-character SQLSTATE codes
				pattern = `([0-9A-Z]{5})`
			case "session_start", "timestamp_unix":
				// Match timestamps or unix epochs
				pattern = `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?|\d+)`
			case "virtual_transaction_id":
				// Match virtual transaction IDs like 3/123
				pattern = `(\d+/\d+)`
			case "transaction_id", "query_id":
				// Match transaction/query IDs (can be 0)
				pattern = `(\d+)`
			case "literal_percent":
				// Literal % character
				pattern = `%`
			default:
				// Generic alphanumeric pattern
				pattern = `([^:\s]+)`
			}

			if fieldName != "literal_percent" {
				fieldMap[fieldName] = groupIndex
				groupIndex++
			}

			// Replace in regex pattern
			quotedSequence := regexp.QuoteMeta(sequence)
			regexPattern = strings.ReplaceAll(regexPattern, quotedSequence, pattern)
		}
	}

	// Add prefixes for CloudWatch and log level if configured
	if p.config.CloudWatchPrefix {
		regexPattern = `(?:^[^\s]+\s+)?` + regexPattern
	}

	if p.config.LogLevelPrefix {
		regexPattern = regexPattern + `(?:(?:LOG|ERROR|WARNING|NOTICE|INFO|DEBUG):\s*)?`
	}

	// Add capture group for the log message content
	regexPattern = regexPattern + `(.*)$`
	fieldMap["content"] = groupIndex

	// Compile regex
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex for format %s: %w", logLinePrefix, err)
	}

	// Store the compiled regex and field mapping
	formatKey := logLinePrefix
	p.regexes[formatKey] = regex

	// Store field mapping as a pattern description
	patternDesc := fmt.Sprintf("Format: %s, Fields: %v", logLinePrefix, fieldMap)
	p.patterns[formatKey] = patternDesc

	return nil
}

// parseEmptyPrefix handles cases where log_line_prefix is empty
func (p *LogFormatParser) parseEmptyPrefix() error {
	// When no prefix is configured, PostgreSQL logs are in format:
	// LOG: duration: 123.456 ms statement: SELECT * FROM users
	// ERROR: relation "nonexistent_table" does not exist
	// STATEMENT: SELECT * FROM nonexistent_table

	var regexPattern string

	// Handle CloudWatch prefix if configured
	if p.config.CloudWatchPrefix {
		regexPattern = `(?:^[^\s]+\s+)?`
	}

	// Handle log level prefix if configured
	if p.config.LogLevelPrefix {
		regexPattern += `(?:(LOG|ERROR|WARNING|NOTICE|INFO|DEBUG):\s*)?`
	} else {
		// Even without LogLevelPrefix config, PostgreSQL might still include level
		// Make it optional for better compatibility
		regexPattern += `(?:(LOG|ERROR|WARNING|NOTICE|INFO|DEBUG):\s*)?`
	}

	// Capture the entire log message content
	regexPattern += `(.*)$`

	// Compile regex
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex for empty prefix: %w", err)
	}

	// Store the compiled regex with empty string key
	formatKey := ""
	p.regexes[formatKey] = regex
	p.patterns[formatKey] = "Format: Empty prefix (no log_line_prefix configured)"

	return nil
}

// ParseLogLine attempts to parse a log line using the configured formats
func (p *LogFormatParser) ParseLogLine(logLine string) (*ParsedLogLine, error) {
	// If auto-detect is enabled, try all patterns
	if p.config.AutoDetect || len(p.regexes) > 1 {
		for format, regex := range p.regexes {
			if result := p.tryParseWithRegex(logLine, regex, format); result != nil {
				return result, nil
			}
		}
		return nil, fmt.Errorf("no matching format found for log line")
	}

	// Use the single configured format
	for format, regex := range p.regexes {
		if result := p.tryParseWithRegex(logLine, regex, format); result != nil {
			return result, nil
		}
		break // Only try the first (and likely only) pattern
	}

	return nil, fmt.Errorf("log line does not match configured format")
}

// tryParseWithRegex attempts to parse a log line with a specific regex
func (p *LogFormatParser) tryParseWithRegex(logLine string, regex *regexp.Regexp, format string) *ParsedLogLine {
	matches := regex.FindStringSubmatch(logLine)
	if len(matches) == 0 {
		return nil
	}

	// Create parsed result
	result := &ParsedLogLine{
		OriginalLine: logLine,
		Format:       format,
		Fields:       make(map[string]string),
	}

	// Handle empty prefix case (no log_line_prefix configured)
	if format == "" {
		// For empty prefix, we only capture log level and content
		if len(matches) >= 2 {
			// matches[1] might be log level (LOG, ERROR, etc.)
			if matches[1] != "" {
				result.Fields["log_level"] = matches[1]
			}
		}
		if len(matches) >= 3 {
			// matches[2] is the content
			result.Fields["content"] = matches[2]
		} else if len(matches) >= 2 {
			// If no log level captured, content is in matches[1]
			result.Fields["content"] = matches[len(matches)-1]
		}
		return result
	}

	// Extract fields based on the format for structured log_line_prefix
	fieldIndex := 1
	for sequence, fieldName := range pgLogEscapeSequences {
		if strings.Contains(format, sequence) && fieldName != "literal_percent" {
			if fieldIndex < len(matches) {
				result.Fields[fieldName] = matches[fieldIndex]
				fieldIndex++
			}
		}
	}

	// The last capture group is always the content
	if len(matches) > fieldIndex {
		result.Fields["content"] = matches[len(matches)-1]
	}

	return result
}

// ParsedLogLine represents a successfully parsed PostgreSQL log line
type ParsedLogLine struct {
	OriginalLine string            `json:"original_line"`
	Format       string            `json:"format"`
	Fields       map[string]string `json:"fields"`
}

// GetField safely retrieves a field value
func (p *ParsedLogLine) GetField(fieldName string) string {
	return p.Fields[fieldName]
}

// GetTimestamp returns the timestamp field (prefers timestamp_ms over timestamp)
func (p *ParsedLogLine) GetTimestamp() string {
	if ts := p.GetField("timestamp_ms"); ts != "" {
		return ts
	}
	return p.GetField("timestamp")
}

// GetRemoteHost returns the remote host field (prefers remote_host over remote_host_only)
func (p *ParsedLogLine) GetRemoteHost() string {
	if host := p.GetField("remote_host"); host != "" {
		return host
	}
	return p.GetField("remote_host_only")
}
