package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/lattiq/sentinel/internal/config"
	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

// PostgreSQLParser is an enhanced parser for PostgreSQL logs with abuse monitoring capabilities
type PostgreSQLParser struct {
	config   *config.QueryLogsConfig
	logger   *logrus.Entry
	features map[string][]string // Legacy feature mapping (deprecated)
	cfg      *config.Config      // Full config for database-aware lookups

	// Dynamic log format parser
	logFormatParser *LogFormatParser

	// Regular expressions for parsing PostgreSQL log formats
	logPrefixRegex   *regexp.Regexp // Legacy fallback
	durationRegex    *regexp.Regexp
	tempFileRegex    *regexp.Regexp
	lockWaitRegex    *regexp.Regexp
	connectionRegex  *regexp.Regexp
	queryRegex       *regexp.Regexp
	tableAccessRegex *regexp.Regexp
}

// NewPostgreSQLParser creates a new enhanced PostgreSQL parser
func NewPostgreSQLParser(cfg *config.QueryLogsConfig, features map[string][]string) *PostgreSQLParser {
	parser := &PostgreSQLParser{
		config:   cfg,
		logger:   logrus.WithField("component", "postgresql_parser"),
		features: features,
	}

	// Compile regular expressions for parsing
	parser.compileRegexes()

	return parser
}

// NewPostgreSQLParserWithConfig creates a database-aware PostgreSQL parser
func NewPostgreSQLParserWithConfig(cfg *config.Config) *PostgreSQLParser {
	parser := &PostgreSQLParser{
		config:   &cfg.DataSources.QueryLogs,
		logger:   logrus.WithField("component", "postgresql_parser"),
		features: cfg.GetFeatureColumns(), // Legacy compatibility
		cfg:      cfg,                     // Full config for database-aware lookups
	}

	// Compile regular expressions for parsing
	parser.compileRegexes()

	return parser
}

// compileRegexes initializes regular expressions for log parsing
func (p *PostgreSQLParser) compileRegexes() {
	// Initialize dynamic log format parser
	var err error
	p.logFormatParser, err = NewLogFormatParser(&p.config.LogFormat)
	if err != nil {
		// Log warning and fall back to legacy parsing
		p.logger.WithError(err).Warn("Failed to initialize dynamic log format parser, using legacy format")
		p.setupLegacyRegex()
	}

	// Duration parsing: Improved to handle all PostgreSQL duration log formats
	// Handles: "duration: 123.456 ms  parse <unnamed>: SELECT ..."
	//          "duration: 123.456 ms  parse stmt_xyz: SELECT ..."
	//          "duration: 123.456 ms  bind stmt_xyz: SELECT ..."
	//          "duration: 123.456 ms  execute stmt_xyz: SELECT ..."
	//          "duration: 123.456 ms" (without statement)
	p.durationRegex = regexp.MustCompile(`duration:\s*(\d+(?:\.\d+)?)\s*ms(?:\s+(?:statement|parse\s+(?:stmt_[^:]*|<[^>]+>)|bind\s+(?:stmt_[^:]*|<[^>]+>)|execute\s+(?:stmt_[^:]*|<[^>]+>)):\s*(.+))?`)

	// Statement-only parsing (when there's no duration) - Updated to handle all PostgreSQL statement formats
	// Handles: "statement: SELECT ...", "execute <unnamed>: SELECT ...", "execute stmt_xyz: SELECT ...", etc.
	p.queryRegex = regexp.MustCompile(`(?i)(?:statement|parse\s+(?:stmt_[^:]*|<[^>]+>)|bind\s+(?:stmt_[^:]*|<[^>]+>)|execute\s+(?:stmt_[^:]*|<[^>]+>)):\s*(.+)`)

	// Temporary file detection: "temporary file: path "base/pgsql_tmp/pgsql_tmpXXXXXX.YY" size 1234567"
	p.tempFileRegex = regexp.MustCompile(`temporary file:\s*path\s*"([^"]+)"\s*size\s*(\d+)`)

	// Lock wait detection: "process 12345 acquired ..." or "process 12345 still waiting for ..." or "deadlock detected"
	p.lockWaitRegex = regexp.MustCompile(`(?i)(?:process\s+(\d+)\s+(acquired|still waiting for)|deadlock detected)\s*(.*)`)

	// Connection events: Enhanced to handle all PostgreSQL connection log formats
	// Handles: "connection received:", "connection authorized:", "connection authenticated:", "disconnection:"
	p.connectionRegex = regexp.MustCompile(`(?i)(connection\s+(?:received|authorized|authenticated)|disconnection):\s*(.*)`)

	// Table access pattern - Focused on data access operations relevant for abuse detection
	// Captures tables from SELECT, INSERT, UPDATE, and JOIN operations (excludes DELETE/TRUNCATE)
	// Handles quoted tables, schema.table notation: schema.table, "schema"."table", table, "table"
	p.tableAccessRegex = regexp.MustCompile(`(?i)(?:(?:SELECT.*?|INSERT\s+)FROM|JOIN|INTO|UPDATE)\s+(?:"?([a-zA-Z_][a-zA-Z0-9_]*)"?\."?([a-zA-Z_][a-zA-Z0-9_]*)"?|"?([a-zA-Z_][a-zA-Z0-9_]*)"?)`)
}

// setupLegacyRegex sets up the hardcoded regex as fallback
func (p *PostgreSQLParser) setupLegacyRegex() {
	// Parse log_line_prefix: '%t:%r:%u@%d:[%p]:'
	// Handle CloudWatch format with optional prefix timestamp and LOG: level
	// Format: TIMESTAMP:REMOTE_HOST:USER@DATABASE:[PROCESS_ID]:LOG: MESSAGE
	// Examples:
	//   "2025-06-26 01:03:20 UTC:10.0.17.40(53154):dbmaster@studio:[8927]:LOG: duration: 0.049 ms"
	//   "2025-06-26 01:04:18 UTC:[local]:rdsadmin@rdsadmin:[8973]:LOG: connection authorized: user=rdsadmin database=rdsadmin"
	//   Also handles direct format without CloudWatch prefix timestamp
	p.logPrefixRegex = regexp.MustCompile(`(?:^[^\s]+\s+)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})? \w+):([^:]+):([^@]+)@([^:]+):\[(\d+)\]:(?:LOG:\s*)?(.*)$`)
}

// ParseLogMessage parses a PostgreSQL log message with enhanced abuse detection
func (p *PostgreSQLParser) ParseLogMessage(rawMessage string, logStream string, timestamp time.Time) (*sentinelTypes.QueryLogEvent, error) {
	// Early filtering: Skip logs that don't contain tables of interest or replication terms
	if !p.shouldProcessLog(rawMessage) {
		return nil, nil // Return nil to indicate this log should be skipped
	}

	event := &sentinelTypes.QueryLogEvent{
		Timestamp:    timestamp.UnixMilli(),
		DatabaseName: "unknown",
		UserName:     "unknown",
		QueryType:    "unknown",
		Duration:     0,
		TableAccess:  []sentinelTypes.TableAccess{},
		ClientIP:     "",
		SSLUsed:      false,
		QuerySize:    len(rawMessage),
	}

	// Try dynamic log format parser first
	if p.logFormatParser != nil {
		if parsedLine, err := p.logFormatParser.ParseLogLine(rawMessage); err == nil {
			p.populateEventFromParsedLine(event, parsedLine)
			return event, nil
		} else {
			p.logger.WithError(err).Debug("Dynamic parser failed, trying legacy parsing")
		}
	}

	// Fallback to legacy regex parsing
	if p.logPrefixRegex != nil {
		if matches := p.logPrefixRegex.FindStringSubmatch(rawMessage); len(matches) >= 7 {
			// matches[1] = timestamp, matches[2] = remote_host, matches[3] = user
			// matches[4] = database, matches[5] = process_id, matches[6] = message

			event.UserName = matches[3]
			event.DatabaseName = matches[4]
			event.ConnectionID = matches[5]

			// Extract client IP from remote host (format: ip(port) or ip)
			if remoteHost := matches[2]; remoteHost != "" {
				if idx := strings.Index(remoteHost, "("); idx > 0 {
					event.ClientIP = remoteHost[:idx]
				} else {
					event.ClientIP = remoteHost
				}
			}

			// Parse the actual log message
			logMessage := matches[6]
			p.parseLogContent(event, logMessage)
			return event, nil
		}
	}

	// Final fallback to simple parsing for non-standard format
	p.parseSimpleFormat(event, rawMessage)
	return event, nil
}

// populateEventFromParsedLine fills a QueryLogEvent from a ParsedLogLine
func (p *PostgreSQLParser) populateEventFromParsedLine(event *sentinelTypes.QueryLogEvent, parsedLine *ParsedLogLine) {
	// Extract basic fields
	if user := parsedLine.GetField("user_name"); user != "" {
		event.UserName = user
	}
	if db := parsedLine.GetField("database_name"); db != "" {
		event.DatabaseName = db
	}
	if pid := parsedLine.GetField("process_id"); pid != "" {
		event.ConnectionID = pid
	}
	if app := parsedLine.GetField("application_name"); app != "" {
		event.ApplicationName = app
	}

	// Extract and clean remote host/IP
	if remoteHost := parsedLine.GetRemoteHost(); remoteHost != "" {
		if idx := strings.Index(remoteHost, "("); idx > 0 {
			event.ClientIP = remoteHost[:idx]
		} else {
			event.ClientIP = remoteHost
		}
	}

	// Parse the log content
	content := parsedLine.GetField("content")
	if content != "" {
		p.parseLogContent(event, content)
	}
}

// parseLogContent parses the content part of the log message
func (p *PostgreSQLParser) parseLogContent(event *sentinelTypes.QueryLogEvent, content string) {
	// Check for duration (with or without statement)
	if matches := p.durationRegex.FindStringSubmatch(content); len(matches) >= 2 {
		if duration, err := strconv.ParseFloat(matches[1], 64); err == nil {
			// PostgreSQL reports duration in milliseconds as float, store as float64
			event.Duration = duration
		}
		// Check if there's a statement in the duration match
		if len(matches) >= 3 && matches[2] != "" {
			p.parseStatement(event, matches[2])
			return
		}

		// Fallback: even if the primary capture group failed, attempt to extract a statement
		// using the generic queryRegex before defaulting to QUERY_COMPLETION. This covers
		// duration lines like "parse <unnamed>: SELECT ..." or "bind <unnamed>: SELECT ..."
		if stmtMatch := p.queryRegex.FindStringSubmatch(content); len(stmtMatch) >= 2 {
			p.parseStatement(event, stmtMatch[1])
			return
		}

		// If only duration without any recognizable statement, mark as query completion
		event.QueryType = "QUERY_COMPLETION"
		return
	}

	// Check for statement without duration
	if matches := p.queryRegex.FindStringSubmatch(content); len(matches) >= 2 {
		p.parseStatement(event, matches[1])
		return
	}

	// Check for connection events
	if matches := p.connectionRegex.FindStringSubmatch(content); len(matches) >= 2 {
		event.QueryType = "CONNECTION_EVENT"
		event.ApplicationName = matches[1]
		return
	}

	// Check for temporary file creation (bulk operation indicator)
	if matches := p.tempFileRegex.FindStringSubmatch(content); len(matches) >= 3 {
		event.QueryType = "TEMP_FILE_CREATED"
		if size, err := strconv.ParseInt(matches[2], 10, 64); err == nil {
			event.RowsAffected = &size // Use size as indicator
		}
		return
	}

	// Check for lock waits (concurrent access patterns)
	if matches := p.lockWaitRegex.FindStringSubmatch(content); len(matches) >= 3 {
		event.QueryType = "LOCK_EVENT"
		event.ConnectionID = matches[1]
		return
	}

	// Default parsing
	event.QueryType = p.extractQueryType(content)
}

// parseStatement analyzes SQL statements for abuse patterns
func (p *PostgreSQLParser) parseStatement(event *sentinelTypes.QueryLogEvent, statement string) {
	// Store raw query for pattern analysis
	event.RawQuery = statement

	// Determine query type
	event.QueryType = p.extractQueryType(statement)

	// Extract table access information with database context
	event.TableAccess = p.extractTableAccessWithContext(statement, event.DatabaseName)

	// Check for replication-related operations
	if p.isReplicationOperation(statement) {
		event.IsReplication = true
		event.ReplicationOp = p.parseReplicationOp(statement)
	}
}

// extractQueryType determines the SQL query type
func (p *PostgreSQLParser) extractQueryType(content string) string {
	upper := strings.ToUpper(strings.TrimSpace(content))

	// Standard DML operations
	if strings.HasPrefix(upper, "SELECT") {
		return "SELECT"
	} else if strings.HasPrefix(upper, "INSERT") {
		return "INSERT"
	} else if strings.HasPrefix(upper, "UPDATE") {
		return "UPDATE"
	} else if strings.HasPrefix(upper, "DELETE") {
		return "DELETE"
	}

	// DDL operations
	if strings.HasPrefix(upper, "CREATE") {
		return "CREATE"
	} else if strings.HasPrefix(upper, "DROP") {
		return "DROP"
	} else if strings.HasPrefix(upper, "ALTER") {
		return "ALTER"
	}

	// Administrative operations
	if strings.HasPrefix(upper, "COPY") {
		return "COPY"
	} else if strings.HasPrefix(upper, "VACUUM") {
		return "VACUUM"
	} else if strings.HasPrefix(upper, "ANALYZE") {
		return "ANALYZE"
	}

	// Replication-specific
	if strings.Contains(upper, "REPLICATION") || strings.Contains(upper, "SLOT") {
		return "REPLICATION"
	}

	return "OTHER"
}

// extractTableAccessWithContext extracts table and column access information with database context
func (p *PostgreSQLParser) extractTableAccessWithContext(statement string, databaseName string) []sentinelTypes.TableAccess {
	var tableAccess []sentinelTypes.TableAccess

	// Extract table names from SQL statement using the enhanced regex
	matches := p.tableAccessRegex.FindAllStringSubmatch(statement, -1)

	for _, match := range matches {
		var tableName string
		var schema string = "public" // Default schema

		// Handle different capture groups from the enhanced regex
		// Group 1 & 2: schema.table format (match[1] = schema, match[2] = table)
		// Group 3: table only format (match[3] = table)
		if len(match) >= 3 && match[1] != "" && match[2] != "" {
			// Schema.table format
			schema = strings.Trim(match[1], `"`)
			tableName = strings.Trim(match[2], `"`)
		} else if len(match) >= 4 && match[3] != "" {
			// Table only format
			tableName = strings.Trim(match[3], `"`)
			// Keep default schema as "public"
		} else {
			continue
		}

		if tableName == "" {
			continue
		}

		// Skip PostgreSQL system catalogs for cleaner analysis (optional)
		// You may want to remove this if you need to track pg_catalog access for abuse detection
		if schema == "pg_catalog" || schema == "information_schema" {
			continue
		}

		// Determine if this is a LattIQ table (use database-aware method if available)
		var isLattIQ bool
		var lattiqCols []string

		if p.cfg != nil {
			// Use database-aware lookup
			isLattIQ = p.cfg.IsLattIQTableWithDatabase(databaseName, schema, tableName)
			if isLattIQ {
				lattiqCols = p.cfg.GetLattIQColumnsWithDatabase(databaseName, schema, tableName)
			}
		} else {
			// Fallback to legacy method
			isLattIQ = p.isLattIQTable(tableName)
			if isLattIQ {
				lattiqCols = p.getLattIQColumns(tableName)
			}
		}

		access := sentinelTypes.TableAccess{
			Schema:     schema,
			Table:      tableName,
			Columns:    []string{}, // TODO: Extract specific columns from SELECT clauses
			AccessType: p.getAccessType(statement),
			IsLattIQ:   isLattIQ,
			LattIQCols: lattiqCols,
		}

		// Avoid duplicate table entries in the same statement
		isDuplicate := false
		for _, existing := range tableAccess {
			if existing.Schema == access.Schema && existing.Table == access.Table {
				isDuplicate = true
				break
			}
		}

		if !isDuplicate {
			tableAccess = append(tableAccess, access)
		}
	}

	return tableAccess
}

// getAccessType determines the type of table access
func (p *PostgreSQLParser) getAccessType(statement string) string {
	upper := strings.ToUpper(statement)
	if strings.Contains(upper, "SELECT") || strings.Contains(upper, "FROM") {
		return "READ"
	} else if strings.Contains(upper, "INSERT") || strings.Contains(upper, "UPDATE") || strings.Contains(upper, "DELETE") {
		return "WRITE"
	}
	return "UNKNOWN"
}

// isLattIQTable checks if a table contains LattIQ features
func (p *PostgreSQLParser) isLattIQTable(tableName string) bool {
	_, exists := p.features[tableName]
	return exists
}

// getLattIQColumns returns LattIQ columns for a table
func (p *PostgreSQLParser) getLattIQColumns(tableName string) []string {
	if cols, exists := p.features[tableName]; exists {
		return cols
	}
	return []string{}
}

// isReplicationOperation checks if the statement is replication-related
func (p *PostgreSQLParser) isReplicationOperation(statement string) bool {
	upper := strings.ToUpper(statement)
	replicationKeywords := []string{
		"CREATE_REPLICATION_SLOT",
		"DROP_REPLICATION_SLOT",
		"IDENTIFY_SYSTEM",
		"READ_REPLICATION_SLOT",
		"TIMELINE_HISTORY",
		"START_REPLICATION",
	}

	for _, keyword := range replicationKeywords {
		if strings.Contains(upper, keyword) {
			return true
		}
	}

	return false
}

// parseReplicationOp extracts replication operation details
func (p *PostgreSQLParser) parseReplicationOp(statement string) *sentinelTypes.ReplicationOp {
	upper := strings.ToUpper(statement)

	op := &sentinelTypes.ReplicationOp{
		Command: "UNKNOWN",
		Options: make(map[string]string),
	}

	if strings.Contains(upper, "CREATE_REPLICATION_SLOT") {
		op.Command = "CREATE_REPLICATION_SLOT"
		// Extract slot name from statement
		parts := strings.Fields(statement)
		if len(parts) >= 3 {
			op.SlotName = parts[2]
		}
	} else if strings.Contains(upper, "START_REPLICATION") {
		op.Command = "START_REPLICATION"
		// Extract slot name and options
		parts := strings.Fields(statement)
		if len(parts) >= 3 {
			op.SlotName = parts[2]
		}
	}

	return op
}

// parseSimpleFormat provides fallback parsing for non-structured logs
func (p *PostgreSQLParser) parseSimpleFormat(event *sentinelTypes.QueryLogEvent, rawMessage string) {
	// Basic query type extraction
	event.QueryType = p.extractQueryType(rawMessage)

	// Look for basic patterns
	if strings.Contains(rawMessage, "duration:") {
		// Try to extract duration from anywhere in the message
		if matches := regexp.MustCompile(`duration:\s*(\d+(?:\.\d+)?)\s*ms`).FindStringSubmatch(rawMessage); len(matches) >= 2 {
			if duration, err := strconv.ParseFloat(matches[1], 64); err == nil {
				// Store duration as float64 to preserve precision
				event.Duration = duration
			}
		}
	}
}

// AnalyzeForAbuse performs enhanced analysis for data abuse patterns
func (p *PostgreSQLParser) AnalyzeForAbuse(event *sentinelTypes.QueryLogEvent) *sentinelTypes.QueryLogAnalysis {
	analysis := &sentinelTypes.QueryLogAnalysis{
		FeatureAccess:     []sentinelTypes.FeatureAccess{},
		SuspiciousPattern: []string{},
		RiskScore:         0.0,
		Anomalies:         []string{},
	}

	// Analyze query characteristics
	p.analyzeDuration(event, analysis)
	p.analyzeLattIQAccess(event, analysis)
	p.analyzeQueryType(event, analysis)
	p.analyzeReplication(event, analysis)
	p.analyzeBulkOperations(event, analysis)

	return analysis
}

// analyzeDuration checks for suspicious query durations
func (p *PostgreSQLParser) analyzeDuration(event *sentinelTypes.QueryLogEvent, analysis *sentinelTypes.QueryLogAnalysis) {
	if event.Duration > 30000 { // 30 seconds
		analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "long_running_query")
		analysis.RiskScore += 20.0
		analysis.Anomalies = append(analysis.Anomalies, fmt.Sprintf("Query duration %.2fms exceeds threshold", event.Duration))
	}

	if event.Duration > 300000 { // 5 minutes - very suspicious
		analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "extremely_long_query")
		analysis.RiskScore += 40.0
		analysis.Anomalies = append(analysis.Anomalies, "Extremely long query duration indicates potential data exfiltration")
	}
}

// analyzeLattIQAccess checks for access to LattIQ features
func (p *PostgreSQLParser) analyzeLattIQAccess(event *sentinelTypes.QueryLogEvent, analysis *sentinelTypes.QueryLogAnalysis) {
	for _, tableAccess := range event.TableAccess {
		if tableAccess.IsLattIQ {
			analysis.RiskScore += 30.0
			analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "lattiq_feature_access")

			featureAccess := sentinelTypes.FeatureAccess{
				TableName:  tableAccess.Table,
				Columns:    tableAccess.LattIQCols,
				AccessType: tableAccess.AccessType,
			}
			analysis.FeatureAccess = append(analysis.FeatureAccess, featureAccess)

			analysis.Anomalies = append(analysis.Anomalies,
				fmt.Sprintf("Access to LattIQ features in table %s", tableAccess.Table))
		}
	}
}

// analyzeQueryType adds risk based on query type
func (p *PostgreSQLParser) analyzeQueryType(event *sentinelTypes.QueryLogEvent, analysis *sentinelTypes.QueryLogAnalysis) {
	switch event.QueryType {
	case "SELECT":
		analysis.RiskScore += 10.0

		// Check for SELECT * patterns (high risk for data exfiltration)
		if event.RawQuery != "" {
			upperQuery := strings.ToUpper(strings.TrimSpace(event.RawQuery))
			if strings.Contains(upperQuery, "SELECT *") || strings.Contains(upperQuery, "SELECT\t*") {
				// Analyze WHERE clause to determine actual risk level
				whereRiskScore, whereRiskPattern, whereAnomaly := p.analyzeWhereClause(upperQuery)

				analysis.RiskScore += whereRiskScore
				analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "select_all_columns")
				if whereRiskPattern != "" {
					analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, whereRiskPattern)
				}
				analysis.Anomalies = append(analysis.Anomalies, whereAnomaly)

				// Even higher risk if accessing multiple tables with SELECT *
				if len(event.TableAccess) > 1 {
					analysis.RiskScore += 20.0
					analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "multi_table_select_all")
					analysis.Anomalies = append(analysis.Anomalies, "SELECT * across multiple tables - high exfiltration risk")
				}
			}
		}

	case "QUERY_COMPLETION":
		// Query completion without statement info - this could indicate:
		// 1. Parsing edge cases
		// 2. Duration-only log entries
		// 3. Potentially obfuscated systematic queries
		// Flag as suspicious if duration suggests actual query execution (not just log artifacts)
		if event.Duration > 10 { // Flag if duration > 10ms (indicates actual query execution)
			analysis.RiskScore += 5.0
			analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "query_completion")

			// Higher risk for queries in systematic extraction range (10-500ms)
			if event.Duration >= 10 && event.Duration <= 500 {
				analysis.RiskScore += 3.0 // Additional risk for systematic extraction pattern
				analysis.Anomalies = append(analysis.Anomalies,
					fmt.Sprintf("Query completion with duration %.2fms - potential systematic extraction pattern", event.Duration))
			}
		}
	case "COPY":
		analysis.RiskScore += 25.0
		analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "bulk_copy_operation")
	case "TEMP_FILE_CREATED":
		analysis.RiskScore += 35.0
		analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "temp_file_creation")
		analysis.Anomalies = append(analysis.Anomalies, "Temporary file creation indicates large data processing")
	}
}

// analyzeReplication checks for replication-related activities
func (p *PostgreSQLParser) analyzeReplication(event *sentinelTypes.QueryLogEvent, analysis *sentinelTypes.QueryLogAnalysis) {
	if event.IsReplication {
		analysis.RiskScore += 50.0
		analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "replication_activity")
		analysis.Anomalies = append(analysis.Anomalies, "Replication activity detected - potential data extraction")
	}
}

// analyzeBulkOperations checks for bulk operation indicators
func (p *PostgreSQLParser) analyzeBulkOperations(event *sentinelTypes.QueryLogEvent, analysis *sentinelTypes.QueryLogAnalysis) {
	if event.RowsAffected != nil && *event.RowsAffected > 10000 {
		analysis.RiskScore += 30.0
		analysis.SuspiciousPattern = append(analysis.SuspiciousPattern, "bulk_operation")
		analysis.Anomalies = append(analysis.Anomalies,
			fmt.Sprintf("Bulk operation affecting %d rows", *event.RowsAffected))
	}
}

// shouldProcessLog checks if the log message should be processed based on early filtering
func (p *PostgreSQLParser) shouldProcessLog(rawMessage string) bool {
	upperMessage := strings.ToUpper(rawMessage)

	// Check for replication-related terms first (always process these)
	replicationKeywords := []string{
		"CREATE_REPLICATION_SLOT",
		"DROP_REPLICATION_SLOT",
		"IDENTIFY_SYSTEM",
		"READ_REPLICATION_SLOT",
		"TIMELINE_HISTORY",
		"START_REPLICATION",
		"REPLICATION",
		"SLOT",
		"COPY",
		"PGDUMP",
	}

	for _, keyword := range replicationKeywords {
		if strings.Contains(upperMessage, keyword) {
			return true
		}
	}

	// Check for LattIQ table names in the raw message
	if p.cfg != nil {
		// Use database-aware config
		for tableName, tableMapping := range p.cfg.Features.Tables {
			// Check for full table name (with or without quotes)
			if strings.Contains(upperMessage, strings.ToUpper(tableName)) ||
				strings.Contains(upperMessage, strings.ToUpper(`"`+tableName+`"`)) {
				return true
			}

			// Check for schema.table format
			fullTableName := fmt.Sprintf("%s.%s", tableMapping.Schema, tableName)
			if strings.Contains(upperMessage, strings.ToUpper(fullTableName)) ||
				strings.Contains(upperMessage, strings.ToUpper(`"`+tableMapping.Schema+`"."`+tableName+`"`)) {
				return true
			}

			// Extract just the table name without schema prefix if it's in schema.table format
			if strings.Contains(tableName, ".") {
				parts := strings.Split(tableName, ".")
				if len(parts) == 2 {
					simpleTableName := parts[1]
					if strings.Contains(upperMessage, strings.ToUpper(simpleTableName)) ||
						strings.Contains(upperMessage, strings.ToUpper(`"`+simpleTableName+`"`)) {
						return true
					}
				}
			}
		}
	} else if p.features != nil {
		// Fallback to legacy features map
		for tableName := range p.features {
			if strings.Contains(upperMessage, strings.ToUpper(tableName)) ||
				strings.Contains(upperMessage, strings.ToUpper(`"`+tableName+`"`)) {
				return true
			}
		}
	}

	// If no LattIQ tables or replication terms found, skip this log
	return false
}

// analyzeWhereClause analyzes the WHERE clause of a SELECT * statement to determine risk level
func (p *PostgreSQLParser) analyzeWhereClause(query string) (float64, string, string) {
	upperQuery := strings.ToUpper(strings.TrimSpace(query))

	// Check for WHERE clause
	whereIndex := strings.Index(upperQuery, "WHERE")
	if whereIndex == -1 {
		// No WHERE clause - extremely high risk (all data)
		return 70.0, "select_all_no_filter", "SELECT * without WHERE clause - maximum data exposure risk"
	}

	// Extract WHERE clause content (until ORDER BY, GROUP BY, HAVING, LIMIT, etc.)
	whereClause := upperQuery[whereIndex+5:]

	// Find the end of WHERE clause
	endKeywords := []string{" ORDER BY", " GROUP BY", " HAVING", " LIMIT", " OFFSET", ";"}
	for _, keyword := range endKeywords {
		if idx := strings.Index(whereClause, keyword); idx != -1 {
			whereClause = whereClause[:idx]
		}
	}

	whereClause = strings.TrimSpace(whereClause)

	// Analyze WHERE clause patterns for risk assessment
	riskScore := 35.0 // Base risk for SELECT * with WHERE
	riskPattern := "select_all_filtered"
	anomaly := "SELECT * with WHERE clause - moderate data exposure risk"

	// Very specific filters (low risk)
	specificPatterns := []string{
		"= '", "= \"", "= [0-9]", // Specific value comparisons
		"IN \\(", // IN clause with specific values
	}
	for _, pattern := range specificPatterns {
		if matched, _ := regexp.MatchString(pattern, whereClause); matched {
			riskScore = 15.0 // Lower risk for specific filters
			riskPattern = "select_all_specific_filter"
			anomaly = "SELECT * with specific WHERE filter - lower data exposure risk"
			break
		}
	}

	// Broad/dangerous filters (high risk)
	broadPatterns := []string{
		"1=1", "1 = 1", // Always true conditions
		"TRUE",   // Always true
		"OR.*OR", // Multiple OR conditions
	}
	for _, pattern := range broadPatterns {
		if matched, _ := regexp.MatchString(pattern, whereClause); matched {
			riskScore = 60.0 // Higher risk for broad filters
			riskPattern = "select_all_broad_filter"
			anomaly = "SELECT * with broad WHERE filter - high data exposure risk"
			break
		}
	}

	// Range queries (medium-high risk)
	rangePatterns := []string{
		"BETWEEN", ">", "<", ">=", "<=", "LIKE '%", "ILIKE '%",
	}
	for _, pattern := range rangePatterns {
		if strings.Contains(whereClause, pattern) {
			if riskScore == 35.0 { // Only if not already categorized
				riskScore = 45.0 // Medium-high risk for range queries
				riskPattern = "select_all_range_filter"
				anomaly = "SELECT * with range/pattern WHERE filter - elevated data exposure risk"
			}
			break
		}
	}

	// Time-based queries (often used for bulk extraction)
	timePatterns := []string{
		"CREATED_AT", "UPDATED_AT", "TIMESTAMP", "DATE", "NOW()", "CURRENT_",
	}
	for _, pattern := range timePatterns {
		if strings.Contains(whereClause, pattern) {
			riskScore += 10.0 // Additional risk for time-based queries
			if !strings.Contains(riskPattern, "time_based") {
				riskPattern += "_time_based"
				anomaly += " (includes time-based filtering)"
			}
			break
		}
	}

	// Sensitive data patterns
	sensitivePatterns := []string{
		"USER", "PASSWORD", "EMAIL", "PHONE", "SSN", "CREDIT", "PAYMENT",
		"PRIVATE", "CONFIDENTIAL", "SECRET", "TOKEN", "KEY",
	}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(whereClause, pattern) {
			riskScore += 15.0 // Additional risk for sensitive data access
			riskPattern += "_sensitive_data"
			anomaly += " (accesses sensitive data fields)"
			break
		}
	}

	return riskScore, riskPattern, anomaly
}
