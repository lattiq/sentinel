package analyzer

import (
	"testing"
	"time"

	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

func TestPatternDetector_AnalyzeQuery_JobMonitorRecords(t *testing.T) {
	detector := NewPatternDetector()

	// Create a test event that matches the real log data
	event := &sentinelTypes.QueryLogEvent{
		Timestamp:    time.Now().UnixMilli(),
		DatabaseName: "studio",
		UserName:     "dbmaster",
		ClientIP:     "10.0.23.181",
		RawQuery:     `SELECT * FROM "job_monitor_records" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2`,
		QueryType:    "SELECT",
		Duration:     25,
		TableAccess: []sentinelTypes.TableAccess{
			{
				Schema:     "public",
				Table:      "job_monitor_records",
				AccessType: "READ",
				IsLattIQ:   true,
				LattIQCols: []string{"next_check", "locked", "deleted_at"},
			},
		},
	}

	// Test that the pattern detector now processes this query
	analysis := detector.AnalyzeQuery(event)

	// Should not be an empty analysis anymore
	if analysis.SessionKey == "" {
		t.Error("Expected non-empty session key, but got empty analysis")
	}

	if analysis.RiskScore < 0 {
		t.Errorf("Expected non-negative risk score, got %f", analysis.RiskScore)
	}

	// Session should be created
	sessionKey := "dbmaster_10.0.23.181_studio"
	if session, exists := detector.userSessions[sessionKey]; !exists {
		t.Error("Expected session to be created")
	} else if len(session.Queries) != 1 {
		t.Errorf("Expected 1 query in session, got %d", len(session.Queries))
	}
}

func TestPatternDetector_SystematicExtraction(t *testing.T) {
	detector := NewPatternDetector()

	// Create multiple similar queries to trigger systematic extraction detection
	baseEvent := &sentinelTypes.QueryLogEvent{
		DatabaseName: "studio",
		UserName:     "dbmaster",
		ClientIP:     "10.0.23.181",
		RawQuery:     `SELECT * FROM "job_monitor_records" WHERE next_check <= $1 AND locked = false AND deleted_at IS NULL LIMIT $2`,
		QueryType:    "SELECT",
		Duration:     25,
		TableAccess: []sentinelTypes.TableAccess{
			{
				Schema:     "public",
				Table:      "job_monitor_records",
				AccessType: "READ",
				IsLattIQ:   true,
				LattIQCols: []string{"next_check", "locked", "deleted_at"},
			},
		},
	}

	// Simulate multiple queries over time
	now := time.Now()
	for i := 0; i < 6; i++ {
		event := *baseEvent
		event.Timestamp = now.Add(time.Duration(i) * time.Minute).UnixMilli()

		analysis := detector.AnalyzeQuery(&event)

		// After enough queries, should detect patterns
		if i >= 5 && len(analysis.SuspiciousPatterns) == 0 {
			t.Errorf("Expected suspicious patterns to be detected after %d queries", i+1)
		}
	}
}

func TestPatternDetector_AccessesConfiguredTables(t *testing.T) {
	detector := NewPatternDetector()

	tests := []struct {
		name     string
		event    *sentinelTypes.QueryLogEvent
		expected bool
	}{
		{
			name: "LattIQ table access",
			event: &sentinelTypes.QueryLogEvent{
				QueryType: "SELECT",
				TableAccess: []sentinelTypes.TableAccess{
					{Table: "job_monitor_records", IsLattIQ: true},
				},
			},
			expected: true,
		},
		{
			name: "Non-LattIQ table access with SELECT",
			event: &sentinelTypes.QueryLogEvent{
				QueryType: "SELECT",
				TableAccess: []sentinelTypes.TableAccess{
					{Table: "some_table", IsLattIQ: false},
				},
			},
			expected: true, // Should still analyze SELECT queries
		},
		{
			name: "SELECT with no table access but has FROM clause",
			event: &sentinelTypes.QueryLogEvent{
				QueryType:   "SELECT",
				RawQuery:    "SELECT * FROM users",
				TableAccess: []sentinelTypes.TableAccess{},
			},
			expected: true, // Fallback should catch this
		},
		{
			name: "Non-SELECT query",
			event: &sentinelTypes.QueryLogEvent{
				QueryType:   "INSERT",
				TableAccess: []sentinelTypes.TableAccess{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.accessesConfiguredTables(tt.event)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
