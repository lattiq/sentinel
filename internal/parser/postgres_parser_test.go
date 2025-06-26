package parser

import (
	"strings"
	"testing"
	"time"

	"github.com/lattiq/sentinel/internal/config"
	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

func TestPostgreSQLParser_ParseLogMessage(t *testing.T) {
	cfg := &config.Config{
		Features: config.FeaturesConfig{
			Tables: map[string]config.TableMapping{
				"users": {
					Database:   "testdb",
					Schema:     "public",
					LattIQCols: []string{"email", "profile_data"},
				},
			},
		},
	}

	parser := NewPostgreSQLParserWithConfig(cfg)

	tests := []struct {
		name          string
		rawMessage    string
		expectedUser  string
		expectedDB    string
		expectedIP    string
		expectedQuery string
		expectedType  string
	}{
		{
			name:          "Standard log format with duration",
			rawMessage:    "2024-01-15 10:30:45 UTC:192.168.1.100(54321):postgres@testdb:[12345]:LOG:duration: 150.123 ms  statement: SELECT * FROM users WHERE id = 1",
			expectedUser:  "postgres",
			expectedDB:    "testdb",
			expectedIP:    "192.168.1.100",
			expectedQuery: "SELECT * FROM users WHERE id = 1",
			expectedType:  "SELECT",
		},
		{
			name:          "Statement without duration",
			rawMessage:    "2025-06-26 05:52:08 UTC:10.0.0.5(52114):admin@mydb:[11578]:LOG:  execute stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: INSERT INTO orders (user_id, amount) VALUES (123, 45.67)",
			expectedUser:  "admin",
			expectedDB:    "mydb",
			expectedIP:    "10.0.0.5",
			expectedQuery: "INSERT INTO orders (user_id, amount) VALUES (123, 45.67)",
			expectedType:  "INSERT",
		},
		{
			name:          "Connection event",
			rawMessage:    "2024-01-15 10:30:45 UTC:192.168.1.50(12345):user@db:[11111]:LOG:connection received: host=192.168.1.50(12345) user=user database=db",
			expectedUser:  "user",
			expectedDB:    "db",
			expectedIP:    "192.168.1.50",
			expectedQuery: "",
			expectedType:  "CONNECTION_EVENT",
		},
		{
			name:          "Temporary file creation",
			rawMessage:    "2024-01-15 10:30:45 UTC:192.168.1.100(54321):postgres@testdb:[12345]:LOG:temporary file: path \"base/pgsql_tmp/pgsql_tmp12345.0\" size 1048576",
			expectedUser:  "postgres",
			expectedDB:    "testdb",
			expectedIP:    "192.168.1.100",
			expectedQuery: "",
			expectedType:  "TEMP_FILE_CREATED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.ParseLogMessage(tt.rawMessage, "test-stream", time.Now())
			if err != nil {
				t.Errorf("ParseLogMessage() error = %v", err)
				return
			}

			// Check if event is nil (filtered out by shouldProcessLog)
			if event == nil {
				t.Errorf("ParseLogMessage() returned nil event for message: %s", tt.rawMessage)
				return
			}

			if event.UserName != tt.expectedUser {
				t.Errorf("Expected user '%s', got '%s'", tt.expectedUser, event.UserName)
			}

			if event.DatabaseName != tt.expectedDB {
				t.Errorf("Expected database '%s', got '%s'", tt.expectedDB, event.DatabaseName)
			}

			if event.ClientIP != tt.expectedIP {
				t.Errorf("Expected IP '%s', got '%s'", tt.expectedIP, event.ClientIP)
			}

			if event.RawQuery != tt.expectedQuery {
				t.Errorf("Expected query '%s', got '%s'", tt.expectedQuery, event.RawQuery)
			}

			if event.QueryType != tt.expectedType {
				t.Errorf("Expected type '%s', got '%s'", tt.expectedType, event.QueryType)
			}
		})
	}
}

func TestPostgreSQLParser_ExtractTableAccess(t *testing.T) {
	cfg := &config.QueryLogsConfig{}
	features := map[string][]string{
		"lattiq_features":     {"feature1", "feature2"},
		"user_profiles":       {"email", "settings"},
		"job_monitor_records": {"next_check", "locked", "deleted_at"},
		"datasets":            {"status", "details"}, // Add datasets table
	}

	parser := NewPostgreSQLParser(cfg, features)

	tests := []struct {
		name           string
		statement      string
		expectedTables []string
		expectedLattIQ bool
	}{
		{
			name:           "SELECT with LattIQ table",
			statement:      "SELECT * FROM lattiq_features WHERE active = true",
			expectedTables: []string{"lattiq_features"},
			expectedLattIQ: true,
		},
		{
			name:           "JOIN query",
			statement:      "SELECT u.name, p.email FROM users u JOIN user_profiles p ON u.id = p.user_id",
			expectedTables: []string{"users", "user_profiles"},
			expectedLattIQ: true, // user_profiles is a LattIQ table
		},
		{
			name:           "Non-LattIQ table",
			statement:      "SELECT * FROM orders WHERE date > '2024-01-01'",
			expectedTables: []string{"orders"},
			expectedLattIQ: false,
		},
		{
			name:           "Quoted table name - job_monitor_records",
			statement:      `SELECT * FROM "job_monitor_records" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2`,
			expectedTables: []string{"job_monitor_records"},
			expectedLattIQ: true, // job_monitor_records is a LattIQ table
		},
		{
			name:           "Mixed quoted and unquoted tables",
			statement:      `SELECT * FROM "job_monitor_records" j JOIN users u ON j.user_id = u.id`,
			expectedTables: []string{"job_monitor_records", "users"},
			expectedLattIQ: true, // job_monitor_records is a LattIQ table
		},
		{
			name:           "Execute unnamed statement - datasets table",
			statement:      "select * from datasets",
			expectedTables: []string{"datasets"},
			expectedLattIQ: true, // datasets should be configured as LattIQ table
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tableAccess := parser.extractTableAccessWithContext(tt.statement, "testdb")

			if len(tableAccess) != len(tt.expectedTables) {
				t.Errorf("Expected %d tables, got %d", len(tt.expectedTables), len(tableAccess))
				return
			}

			hasLattIQ := false
			for _, access := range tableAccess {
				if access.IsLattIQ {
					hasLattIQ = true
					break
				}
			}

			if hasLattIQ != tt.expectedLattIQ {
				t.Errorf("Expected LattIQ access %v, got %v", tt.expectedLattIQ, hasLattIQ)
			}
		})
	}
}

func TestPostgreSQLParser_AnalyzeForAbuse(t *testing.T) {
	cfg := &config.QueryLogsConfig{}
	features := map[string][]string{
		"sensitive_data": {"credit_card", "ssn"},
	}

	parser := NewPostgreSQLParser(cfg, features)

	tests := []struct {
		name           string
		event          *sentinelTypes.QueryLogEvent
		expectRisk     float64
		expectPatterns []string
	}{
		{
			name: "LattIQ feature access",
			event: &sentinelTypes.QueryLogEvent{
				QueryType: "SELECT",
				TableAccess: []sentinelTypes.TableAccess{
					{
						Table:      "sensitive_data",
						IsLattIQ:   true,
						LattIQCols: []string{"credit_card", "ssn"},
						AccessType: "READ",
					},
				},
				Duration: 1000,
			},
			expectRisk:     40.0, // 10 for SELECT + 30 for LattIQ
			expectPatterns: []string{"lattiq_feature_access"},
		},
		{
			name: "Long running query",
			event: &sentinelTypes.QueryLogEvent{
				QueryType: "SELECT",
				Duration:  35000, // 35 seconds
			},
			expectRisk:     30.0, // 10 for SELECT + 20 for long duration
			expectPatterns: []string{"long_running_query"},
		},
		{
			name: "Replication activity",
			event: &sentinelTypes.QueryLogEvent{
				QueryType:     "REPLICATION",
				IsReplication: true,
				ReplicationOp: &sentinelTypes.ReplicationOp{
					Command:  "START_REPLICATION",
					SlotName: "test_slot",
				},
			},
			expectRisk:     50.0,
			expectPatterns: []string{"replication_activity"},
		},
		{
			name: "Temporary file creation",
			event: &sentinelTypes.QueryLogEvent{
				QueryType:    "TEMP_FILE_CREATED",
				RowsAffected: func() *int64 { size := int64(1048576); return &size }(),
			},
			expectRisk:     35.0,
			expectPatterns: []string{"temp_file_creation"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := parser.AnalyzeForAbuse(tt.event)

			if analysis.RiskScore < tt.expectRisk {
				t.Errorf("Expected risk score >= %f, got %f", tt.expectRisk, analysis.RiskScore)
			}

			for _, expectedPattern := range tt.expectPatterns {
				found := false
				for _, pattern := range analysis.SuspiciousPattern {
					if pattern == expectedPattern {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected pattern '%s' not found in %v", expectedPattern, analysis.SuspiciousPattern)
				}
			}
		})
	}
}

func TestPostgreSQLParser_LogPrefixRegex(t *testing.T) {
	cfg := &config.QueryLogsConfig{}
	parser := NewPostgreSQLParser(cfg, nil)

	// Force the use of legacy regex by setting up manually
	parser.setupLegacyRegex()

	tests := []struct {
		name         string
		logLine      string
		shouldMatch  bool
		expectedIP   string
		expectedUser string
		expectedDB   string
	}{
		{
			name:         "Standard format",
			logLine:      "2024-01-15 10:30:45 UTC:192.168.1.100(54321):postgres@testdb:[12345]:statement: SELECT 1",
			shouldMatch:  true,
			expectedIP:   "192.168.1.100",
			expectedUser: "postgres",
			expectedDB:   "testdb",
		},
		{
			name:         "With milliseconds",
			logLine:      "2024-01-15 10:30:45.123 EST:10.0.0.1(12345):admin@mydb:[67890]:duration: 100.0 ms",
			shouldMatch:  true,
			expectedIP:   "10.0.0.1",
			expectedUser: "admin",
			expectedDB:   "mydb",
		},
		{
			name:         "IP without port",
			logLine:      "2024-01-15 10:30:45 UTC:192.168.1.100:user@db:[11111]:connection received",
			shouldMatch:  true,
			expectedIP:   "192.168.1.100",
			expectedUser: "user",
			expectedDB:   "db",
		},
		{
			name:         "CloudWatch format with LOG prefix",
			logLine:      "2025-06-25T15:53:53.000+05:30    2025-06-25 10:23:53 UTC:10.0.23.181(52658):dbmaster@studio:[32016]:LOG: duration: 0.049 ms",
			shouldMatch:  true,
			expectedIP:   "10.0.23.181",
			expectedUser: "dbmaster",
			expectedDB:   "studio",
		},
		{
			name:         "CloudWatch format with statement",
			logLine:      "2025-06-25T15:53:53.000+05:30    2025-06-25 10:23:53 UTC:10.0.23.181(52658):dbmaster@studio:[32016]:LOG: statement: SELECT * FROM users WHERE id = 1",
			shouldMatch:  true,
			expectedIP:   "10.0.23.181",
			expectedUser: "dbmaster",
			expectedDB:   "studio",
		},
		{
			name:        "Invalid format",
			logLine:     "Some random log message",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := parser.logPrefixRegex.FindStringSubmatch(tt.logLine)

			if tt.shouldMatch {
				if len(matches) < 7 {
					t.Errorf("Expected regex to match, but got %d groups", len(matches))
					return
				}

				// Extract IP from remote host
				remoteHost := matches[2]
				var actualIP string
				if idx := len(remoteHost); idx > 0 {
					if parenIdx := len(remoteHost); parenIdx > 0 {
						for i, char := range remoteHost {
							if char == '(' {
								actualIP = remoteHost[:i]
								break
							}
						}
						if actualIP == "" {
							actualIP = remoteHost
						}
					}
				}

				if actualIP != tt.expectedIP {
					t.Errorf("Expected IP '%s', got '%s'", tt.expectedIP, actualIP)
				}

				if matches[3] != tt.expectedUser {
					t.Errorf("Expected user '%s', got '%s'", tt.expectedUser, matches[3])
				}

				if matches[4] != tt.expectedDB {
					t.Errorf("Expected database '%s', got '%s'", tt.expectedDB, matches[4])
				}
			} else {
				if len(matches) > 0 {
					t.Errorf("Expected regex not to match, but got %d groups", len(matches))
				}
			}
		})
	}
}

func TestPostgreSQLParser_ReplicationDetection(t *testing.T) {
	cfg := &config.QueryLogsConfig{}
	parser := NewPostgreSQLParser(cfg, nil)

	tests := []struct {
		name              string
		statement         string
		expectReplication bool
		expectedCommand   string
	}{
		{
			name:              "CREATE_REPLICATION_SLOT",
			statement:         "CREATE_REPLICATION_SLOT test_slot LOGICAL pgoutput",
			expectReplication: true,
			expectedCommand:   "CREATE_REPLICATION_SLOT",
		},
		{
			name:              "START_REPLICATION",
			statement:         "START_REPLICATION SLOT test_slot LOGICAL 0/0",
			expectReplication: true,
			expectedCommand:   "START_REPLICATION",
		},
		{
			name:              "Normal SELECT",
			statement:         "SELECT * FROM users",
			expectReplication: false,
		},
		{
			name:              "IDENTIFY_SYSTEM",
			statement:         "IDENTIFY_SYSTEM",
			expectReplication: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isReplication := parser.isReplicationOperation(tt.statement)

			if isReplication != tt.expectReplication {
				t.Errorf("Expected replication detection %v, got %v", tt.expectReplication, isReplication)
			}

			if tt.expectReplication && tt.expectedCommand != "" {
				replicationOp := parser.parseReplicationOp(tt.statement)
				if replicationOp.Command != tt.expectedCommand {
					t.Errorf("Expected command '%s', got '%s'", tt.expectedCommand, replicationOp.Command)
				}
			}
		})
	}
}

func TestPostgreSQLParser_PreparedStatementRegexFix(t *testing.T) {
	cfg := &config.QueryLogsConfig{}
	features := map[string][]string{
		"job_monitor_records": {"next_check", "locked", "deleted_at"},
	}
	parser := NewPostgreSQLParser(cfg, features)

	tests := []struct {
		name               string
		content            string
		expectType         string
		expectDuration     float64 // Changed from int64 to float64
		shouldExtractQuery bool
	}{
		{
			name:               "Parse statement with duration",
			content:            "duration: 0.095 ms  parse stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: SELECT * FROM \"job_monitor_records\" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2",
			expectType:         "SELECT",
			expectDuration:     0.095, // Updated to match actual parsed value
			shouldExtractQuery: true,
		},
		{
			name:               "Bind statement with duration",
			content:            "duration: 0.160 ms  bind stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: SELECT * FROM \"job_monitor_records\" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2",
			expectType:         "SELECT",
			expectDuration:     0.160, // Updated to match actual parsed value
			shouldExtractQuery: true,
		},
		{
			name:               "Execute statement",
			content:            "execute stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: SELECT * FROM \"job_monitor_records\" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2",
			expectType:         "SELECT",
			expectDuration:     0.0, // No duration in execute statement
			shouldExtractQuery: true,
		},
		{
			name:               "Duration only without statement",
			content:            "duration: 0.042 ms",
			expectType:         "QUERY_COMPLETION",
			expectDuration:     0.042, // Updated to match actual parsed value
			shouldExtractQuery: false,
		},
		{
			name:               "Suspicious systematic extraction duration",
			content:            "duration: 50.0 ms",
			expectType:         "QUERY_COMPLETION",
			expectDuration:     50.0, // Updated to match actual parsed value
			shouldExtractQuery: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &sentinelTypes.QueryLogEvent{
				DatabaseName: "test",
				UserName:     "test",
				QueryType:    "unknown",
			}

			parser.parseLogContent(event, tt.content)

			if event.QueryType != tt.expectType {
				t.Errorf("Expected query type '%s', got '%s'", tt.expectType, event.QueryType)
			}

			if event.Duration != tt.expectDuration {
				t.Errorf("Expected duration %.3f, got %.3f", tt.expectDuration, event.Duration)
			}

			if tt.shouldExtractQuery {
				if event.RawQuery == "" {
					t.Errorf("Expected query to be extracted, but RawQuery is empty")
				}
				if !strings.Contains(event.RawQuery, "SELECT") {
					t.Errorf("Expected extracted query to contain SELECT, got: %s", event.RawQuery)
				}
			}

			// Test suspicious flagging logic
			analysis := parser.AnalyzeForAbuse(event)
			if tt.expectType == "QUERY_COMPLETION" {
				hasSuspiciousCompletion := false
				for _, pattern := range analysis.SuspiciousPattern {
					if pattern == "query_completion" {
						hasSuspiciousCompletion = true
						break
					}
				}

				if event.Duration <= 10 {
					// Very short duration (likely log artifacts) should not be flagged as suspicious
					if hasSuspiciousCompletion {
						t.Errorf("Very short duration QUERY_COMPLETION should not be flagged as suspicious")
					}
				} else if event.Duration > 10 {
					// Queries with measurable duration should be flagged as suspicious
					if !hasSuspiciousCompletion {
						t.Errorf("QUERY_COMPLETION with duration %.2fms should be flagged as suspicious", event.Duration)
					}

					// Check for systematic extraction pattern detection
					if event.Duration >= 10 && event.Duration <= 500 {
						foundSystematicAnomaly := false
						for _, anomaly := range analysis.Anomalies {
							if strings.Contains(anomaly, "systematic extraction pattern") {
								foundSystematicAnomaly = true
								break
							}
						}
						if !foundSystematicAnomaly {
							t.Errorf("QUERY_COMPLETION with duration %.2fms should trigger systematic extraction anomaly", event.Duration)
						}
					}
				}
			}
		})
	}
}

// Add a new test specifically for the execute <unnamed> format
func TestPostgreSQLParser_ExecuteUnnamedFormat(t *testing.T) {
	cfg := &config.QueryLogsConfig{}
	features := map[string][]string{
		"datasets": {"status", "details"},
	}

	parser := NewPostgreSQLParser(cfg, features)

	// Test the exact log message format from the issue
	rawMessage := "2025-06-26 01:03:32 UTC:10.0.17.40(53154):dbmaster@studio:[8927]:LOG:  execute <unnamed>: select * from datasets"

	event, err := parser.ParseLogMessage(rawMessage, "test-stream", time.Now())
	if err != nil {
		t.Fatalf("Failed to parse log message: %v", err)
	}

	// Verify basic parsing
	if event.UserName != "dbmaster" {
		t.Errorf("Expected user 'dbmaster', got '%s'", event.UserName)
	}
	if event.DatabaseName != "studio" {
		t.Errorf("Expected database 'studio', got '%s'", event.DatabaseName)
	}
	if event.QueryType != "SELECT" {
		t.Errorf("Expected query type 'SELECT', got '%s'", event.QueryType)
	}

	// Verify table extraction
	if len(event.TableAccess) != 1 {
		t.Fatalf("Expected 1 table access, got %d", len(event.TableAccess))
	}

	tableAccess := event.TableAccess[0]
	if tableAccess.Table != "datasets" {
		t.Errorf("Expected table 'datasets', got '%s'", tableAccess.Table)
	}
	if !tableAccess.IsLattIQ {
		t.Errorf("Expected datasets to be marked as LattIQ table")
	}

	// Verify raw query extraction
	expectedQuery := "select * from datasets"
	if event.RawQuery != expectedQuery {
		t.Errorf("Expected raw query '%s', got '%s'", expectedQuery, event.RawQuery)
	}

	// Test the abuse analysis
	analysis := parser.AnalyzeForAbuse(event)

	// Should have high risk due to SELECT * + LattIQ access
	if analysis.RiskScore < 50.0 {
		t.Errorf("Expected high risk score for SELECT * on LattIQ table, got %.1f", analysis.RiskScore)
	}

	// Should have SELECT * pattern detection
	hasSelectAllPattern := false
	for _, pattern := range analysis.SuspiciousPattern {
		if pattern == "select_all_columns" {
			hasSelectAllPattern = true
			break
		}
	}
	if !hasSelectAllPattern {
		t.Errorf("Expected 'select_all_columns' suspicious pattern to be detected")
	}
}

func TestPostgreSQLParser_WhereClauseAnalysis(t *testing.T) {
	cfg := &config.QueryLogsConfig{}
	features := map[string][]string{
		"sensitive_data": {"credit_card", "ssn", "user_id"},
	}

	parser := NewPostgreSQLParser(cfg, features)

	tests := []struct {
		name            string
		query           string
		expectedRisk    float64
		expectedPattern string
		expectedAnomaly string
	}{
		{
			name:            "SELECT * without WHERE clause",
			query:           "SELECT * FROM sensitive_data",
			expectedRisk:    70.0,
			expectedPattern: "select_all_no_filter",
			expectedAnomaly: "SELECT * without WHERE clause - maximum data exposure risk",
		},
		{
			name:            "SELECT * with specific ID filter",
			query:           "SELECT * FROM sensitive_data WHERE id = 123",
			expectedRisk:    15.0,
			expectedPattern: "select_all_specific_filter",
			expectedAnomaly: "SELECT * with specific WHERE filter - lower data exposure risk",
		},
		{
			name:            "SELECT * with string filter",
			query:           "SELECT * FROM sensitive_data WHERE name = 'john'",
			expectedRisk:    15.0,
			expectedPattern: "select_all_specific_filter",
			expectedAnomaly: "SELECT * with specific WHERE filter - lower data exposure risk",
		},
		{
			name:            "SELECT * with IN clause",
			query:           "SELECT * FROM sensitive_data WHERE id IN (1, 2, 3)",
			expectedRisk:    15.0,
			expectedPattern: "select_all_specific_filter",
			expectedAnomaly: "SELECT * with specific WHERE filter - lower data exposure risk",
		},
		{
			name:            "SELECT * with broad filter (always true)",
			query:           "SELECT * FROM sensitive_data WHERE 1=1",
			expectedRisk:    60.0,
			expectedPattern: "select_all_broad_filter",
			expectedAnomaly: "SELECT * with broad WHERE filter - high data exposure risk",
		},
		{
			name:            "SELECT * with range filter",
			query:           "SELECT * FROM sensitive_data WHERE created_at > '2024-01-01'",
			expectedRisk:    55.0, // 45.0 base + 10.0 for time-based
			expectedPattern: "select_all_range_filter_time_based",
			expectedAnomaly: "SELECT * with range/pattern WHERE filter - elevated data exposure risk (includes time-based filtering)",
		},
		{
			name:            "SELECT * with LIKE pattern",
			query:           "SELECT * FROM sensitive_data WHERE email LIKE '%@company.com'",
			expectedRisk:    60.0, // 45.0 base + 15.0 for sensitive data (EMAIL)
			expectedPattern: "select_all_range_filter_sensitive_data",
			expectedAnomaly: "SELECT * with range/pattern WHERE filter - elevated data exposure risk (accesses sensitive data fields)",
		},
		{
			name:            "SELECT * with sensitive data access",
			query:           "SELECT * FROM sensitive_data WHERE user_id = 123",
			expectedRisk:    30.0, // 15.0 base + 15.0 for sensitive data
			expectedPattern: "select_all_specific_filter_sensitive_data",
			expectedAnomaly: "SELECT * with specific WHERE filter - lower data exposure risk (accesses sensitive data fields)",
		},
		{
			name:            "SELECT * with moderate filter",
			query:           "SELECT * FROM sensitive_data WHERE status = 'active'",
			expectedRisk:    15.0,
			expectedPattern: "select_all_specific_filter",
			expectedAnomaly: "SELECT * with specific WHERE filter - lower data exposure risk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			riskScore, riskPattern, anomaly := parser.analyzeWhereClause(tt.query)

			if riskScore != tt.expectedRisk {
				t.Errorf("Expected risk score %f, got %f", tt.expectedRisk, riskScore)
			}

			if riskPattern != tt.expectedPattern {
				t.Errorf("Expected pattern '%s', got '%s'", tt.expectedPattern, riskPattern)
			}

			if anomaly != tt.expectedAnomaly {
				t.Errorf("Expected anomaly '%s', got '%s'", tt.expectedAnomaly, anomaly)
			}
		})
	}
}

func TestPostgreSQLParser_DebugSpecificLogMessage(t *testing.T) {
	cfg := &config.QueryLogsConfig{}
	features := map[string][]string{
		"job_monitor_records": {"version", "status"},
	}

	parser := NewPostgreSQLParser(cfg, features)

	// Test with the exact log message from the new JSON that's still showing duration 0
	rawMessage := `2025-06-26 05:09:23 UTC:10.0.23.181(46102):dbmaster@studio:[9683]:LOG:  duration: 0.140 ms  bind stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: SELECT * FROM "job_monitor_records" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2`

	event, err := parser.ParseLogMessage(rawMessage, "test-stream", time.Now())
	if err != nil {
		t.Errorf("ParseLogMessage() error = %v", err)
		return
	}

	t.Logf("Raw message: %s", rawMessage)
	t.Logf("Parsed duration: %.3f", event.Duration)
	t.Logf("Database name: %s", event.DatabaseName)
	t.Logf("User name: %s", event.UserName)
	t.Logf("Client IP: %s", event.ClientIP)
	t.Logf("Query type: %s", event.QueryType)
	t.Logf("Raw query: %s", event.RawQuery)

	// Expected: 0.140 (now that we store as float64)
	if event.Duration == 0.140 {
		t.Logf("Duration is 0.140 - this is correct for 0.140ms stored as float64")
	} else {
		t.Errorf("Expected duration 0.140 ms, got %.3f ms", event.Duration)
	}

	if event.Duration < 0 {
		t.Errorf("Duration should not be negative: %.3f", event.Duration)
	}

	// Test with a duration that should round to 1
	rawMessage2 := `2025-06-26 05:09:23 UTC:10.0.23.181(46102):dbmaster@studio:[9683]:LOG:  duration: 0.685 ms  bind stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: SELECT * FROM "job_monitor_records" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2`

	event2, err := parser.ParseLogMessage(rawMessage2, "test-stream", time.Now())
	if err != nil {
		t.Errorf("ParseLogMessage() error = %v", err)
		return
	}

	t.Logf("Raw message 2: %s", rawMessage2)
	t.Logf("Parsed duration 2: %.3f", event2.Duration)

	// Expected: 0.685 (now that we store as float64)
	if event2.Duration != 0.685 {
		t.Errorf("Expected duration 0.685 ms for 0.685ms, got %.3f ms", event2.Duration)
	}
}

func TestPostgreSQLParser_DurationFixVerification(t *testing.T) {
	cfg := &config.QueryLogsConfig{}
	features := map[string][]string{
		"job_monitor_records": {"version", "status"},
	}

	parser := NewPostgreSQLParser(cfg, features)

	tests := []struct {
		name             string
		rawMessage       string
		expectedDuration float64
	}{
		{
			name:             "Original 0.140ms from JSON",
			rawMessage:       `2025-06-26 05:09:23 UTC:10.0.23.181(46102):dbmaster@studio:[9683]:LOG:  duration: 0.140 ms  bind stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: SELECT * FROM "job_monitor_records" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2`,
			expectedDuration: 0.140,
		},
		{
			name:             "Original 0.103ms from JSON",
			rawMessage:       `2025-06-26 04:56:08 UTC:10.0.23.181(34360):dbmaster@studio:[8978]:LOG:  duration: 0.103 ms  parse stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: SELECT * FROM "job_monitor_records" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2`,
			expectedDuration: 0.103,
		},
		{
			name:             "Original 0.146ms from JSON",
			rawMessage:       `2025-06-26 04:56:08 UTC:10.0.23.181(34360):dbmaster@studio:[8978]:LOG:  duration: 0.146 ms  bind stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: SELECT * FROM "job_monitor_records" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2`,
			expectedDuration: 0.146,
		},
		{
			name:             "Original 0.685ms from JSON",
			rawMessage:       `2025-06-26 04:57:24 UTC:10.0.23.181(42428):dbmaster@studio:[9212]:LOG:  duration: 0.685 ms  bind stmt_412ef5831f2c95842a65241e170ab121530498d6429579c0: SELECT * FROM "job_monitor_records" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2`,
			expectedDuration: 0.685,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.ParseLogMessage(tt.rawMessage, "test-stream", time.Now())
			if err != nil {
				t.Errorf("ParseLogMessage() error = %v", err)
				return
			}

			if event.Duration != tt.expectedDuration {
				t.Errorf("Expected duration %.3f ms, got %.3f ms", tt.expectedDuration, event.Duration)
			} else {
				t.Logf("✓ Duration correctly parsed: %.3f ms", event.Duration)
			}
		})
	}
}
