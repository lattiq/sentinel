package analyzer

import (
	"crypto/md5"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

// PatternDetector identifies sophisticated attack patterns like systematic data exfiltration
type PatternDetector struct {
	mu     sync.RWMutex
	logger *logrus.Entry

	// Track query patterns by user/IP combinations
	userSessions map[string]*SessionTracker

	// Detection thresholds
	config PatternConfig
}

// PatternConfig defines detection thresholds and windows
type PatternConfig struct {
	// Systematic extraction detection
	MinSimilarQueries    int           // Minimum similar queries to trigger alert
	TimeWindow           time.Duration // Time window to analyze patterns
	MaxSessionInactivity time.Duration // Max time between queries in same session

	// Pattern matching
	SimilarityThreshold   float64 // 0.0-1.0, higher = more similar required
	MaxConcurrentSessions int     // Maximum tracked sessions
}

// SessionTracker tracks query patterns for a specific user/IP combination
type SessionTracker struct {
	UserID       string
	ClientIP     string
	DatabaseName string

	// Query pattern tracking
	Queries      []QueryPattern
	FirstSeen    time.Time
	LastActivity time.Time

	// Pattern detection state
	SuspiciousPatterns []string
	RiskAccumulator    float64
	AlertsTriggered    []string
}

// QueryPattern represents a normalized query pattern for comparison
type QueryPattern struct {
	Timestamp       time.Time
	OriginalQuery   string
	NormalizedQuery string
	QueryHash       string
	TablesAccessed  []string
	HasOrderBy      bool
	HasLimit        bool
	HasOffset       bool
	LimitValue      *int64
	OffsetValue     *int64
	Duration        float64
	IsLattIQAccess  bool
}

// PatternAnalysis represents the result of pattern analysis
type PatternAnalysis struct {
	SessionKey         string                 `json:"session_key"`
	SuspiciousPatterns []string               `json:"suspicious_patterns"`
	RiskScore          float64                `json:"risk_score"`
	Confidence         float64                `json:"confidence"`
	Details            map[string]interface{} `json:"details"`
}

// NewPatternDetector creates a new pattern detector
func NewPatternDetector() *PatternDetector {
	return &PatternDetector{
		logger:       logrus.WithField("component", "pattern_detector"),
		userSessions: make(map[string]*SessionTracker),
		config: PatternConfig{
			MinSimilarQueries:     5,
			TimeWindow:            15 * time.Minute,
			MaxSessionInactivity:  5 * time.Minute,
			SimilarityThreshold:   0.85,
			MaxConcurrentSessions: 1000,
		},
	}
}

// AnalyzeQuery analyzes a query for systematic extraction patterns
func (pd *PatternDetector) AnalyzeQuery(event *sentinelTypes.QueryLogEvent) *PatternAnalysis {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	// Check if this query accesses any configured LattIQ tables
	if !pd.accessesConfiguredTables(event) {
		// Return empty analysis for queries that don't access configured tables
		return &PatternAnalysis{
			SessionKey:         "",
			SuspiciousPatterns: []string{},
			RiskScore:          0.0,
			Confidence:         0.0,
			Details:            make(map[string]interface{}),
		}
	}

	// Create session key
	sessionKey := fmt.Sprintf("%s_%s_%s", event.UserName, event.ClientIP, event.DatabaseName)

	// Get or create session tracker
	session := pd.getOrCreateSession(sessionKey, event)

	// Update session activity
	session.LastActivity = time.UnixMilli(event.Timestamp)

	// Create query pattern
	pattern := pd.createQueryPattern(event)
	session.Queries = append(session.Queries, pattern)

	// Clean old sessions periodically
	pd.cleanOldSessions()

	// Analyze for systematic extraction
	analysis := pd.detectSystematicExtraction(session)

	return analysis
}

// createQueryPattern creates a normalized query pattern for comparison
func (pd *PatternDetector) createQueryPattern(event *sentinelTypes.QueryLogEvent) QueryPattern {
	// Extract query from the event
	originalQuery := event.RawQuery

	// Normalize the query for pattern matching
	normalized := pd.normalizeQuery(originalQuery)

	// Create hash for quick comparison
	hash := fmt.Sprintf("%x", md5.Sum([]byte(normalized)))

	// Analyze query structure
	hasOrderBy := pd.containsOrderBy(originalQuery)
	hasLimit := pd.containsLimit(originalQuery)
	hasOffset := pd.containsOffset(originalQuery)

	limitValue := pd.extractLimitValue(originalQuery)
	offsetValue := pd.extractOffsetValue(originalQuery)

	// Check if accessing LattIQ features
	isLattIQAccess := false
	tablesAccessed := make([]string, 0)
	for _, tableAccess := range event.TableAccess {
		tablesAccessed = append(tablesAccessed, tableAccess.Table)
		if tableAccess.IsLattIQ {
			isLattIQAccess = true
		}
	}

	return QueryPattern{
		Timestamp:       time.UnixMilli(event.Timestamp),
		OriginalQuery:   originalQuery,
		NormalizedQuery: normalized,
		QueryHash:       hash,
		TablesAccessed:  tablesAccessed,
		HasOrderBy:      hasOrderBy,
		HasLimit:        hasLimit,
		HasOffset:       hasOffset,
		LimitValue:      limitValue,
		OffsetValue:     offsetValue,
		Duration:        event.Duration,
		IsLattIQAccess:  isLattIQAccess,
	}
}

// normalizeQuery creates a normalized version of the query for pattern matching
func (pd *PatternDetector) normalizeQuery(query string) string {
	normalized := strings.ToUpper(strings.TrimSpace(query))

	// Replace variable parts with placeholders
	// Replace LIMIT values: LIMIT 1000 -> LIMIT ?
	limitRegex := regexp.MustCompile(`LIMIT\s+\d+`)
	normalized = limitRegex.ReplaceAllString(normalized, "LIMIT ?")

	// Replace OFFSET values: OFFSET 5000 -> OFFSET ?
	offsetRegex := regexp.MustCompile(`OFFSET\s+\d+`)
	normalized = offsetRegex.ReplaceAllString(normalized, "OFFSET ?")

	// Replace literal values in WHERE clauses
	whereRegex := regexp.MustCompile(`=\s*'[^']+'`)
	normalized = whereRegex.ReplaceAllString(normalized, "= ?")

	whereNumRegex := regexp.MustCompile(`=\s*\d+`)
	normalized = whereNumRegex.ReplaceAllString(normalized, "= ?")

	// Replace IN clauses
	inRegex := regexp.MustCompile(`IN\s*\([^)]+\)`)
	normalized = inRegex.ReplaceAllString(normalized, "IN (?)")

	return normalized
}

// detectSystematicExtraction analyzes query patterns for systematic data extraction
func (pd *PatternDetector) detectSystematicExtraction(session *SessionTracker) *PatternAnalysis {
	analysis := &PatternAnalysis{
		SessionKey:         fmt.Sprintf("%s_%s", session.UserID, session.ClientIP),
		SuspiciousPatterns: []string{},
		RiskScore:          0.0,
		Confidence:         0.0,
		Details:            make(map[string]interface{}),
	}

	if len(session.Queries) < pd.config.MinSimilarQueries {
		return analysis
	}

	// Check for systematic ORDER BY + LIMIT/OFFSET patterns
	pd.detectOrderByProgression(session, analysis)

	// Check for rapid sequential access to same tables
	pd.detectRapidSequentialAccess(session, analysis)

	// Check for systematic pagination patterns
	pd.detectPaginationPatterns(session, analysis)

	// Check for LattIQ feature enumeration
	pd.detectLattIQEnumeration(session, analysis)

	return analysis
}

// detectOrderByProgression detects systematic progression through ordered data
func (pd *PatternDetector) detectOrderByProgression(session *SessionTracker, analysis *PatternAnalysis) {
	recentQueries := pd.getRecentQueries(session.Queries, pd.config.TimeWindow)

	if len(recentQueries) < pd.config.MinSimilarQueries {
		return
	}

	// Group by normalized query pattern
	patternGroups := make(map[string][]QueryPattern)
	for _, query := range recentQueries {
		if query.HasOrderBy && (query.HasLimit || query.HasOffset) {
			patternGroups[query.NormalizedQuery] = append(patternGroups[query.NormalizedQuery], query)
		}
	}

	// Check each pattern group for systematic progression
	for pattern, queries := range patternGroups {
		if len(queries) >= pd.config.MinSimilarQueries {
			if pd.isSystematicProgression(queries) {
				analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns, "systematic_order_by_extraction")
				analysis.RiskScore += 60.0
				analysis.Confidence = 0.9

				analysis.Details["systematic_pattern"] = pattern
				analysis.Details["query_count"] = len(queries)
				analysis.Details["time_span"] = queries[len(queries)-1].Timestamp.Sub(queries[0].Timestamp).String()

				// Higher risk if accessing LattIQ features
				hasLattIQAccess := false
				for _, q := range queries {
					if q.IsLattIQAccess {
						hasLattIQAccess = true
						break
					}
				}

				if hasLattIQAccess {
					analysis.RiskScore += 40.0
					analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns, "lattiq_systematic_extraction")
				}
			}
		}
	}
}

// isSystematicProgression checks if queries show systematic progression through data
func (pd *PatternDetector) isSystematicProgression(queries []QueryPattern) bool {
	if len(queries) < 3 {
		return false
	}

	// Sort by timestamp
	sort.Slice(queries, func(i, j int) bool {
		return queries[i].Timestamp.Before(queries[j].Timestamp)
	})

	// Check for consistent LIMIT values
	limitValues := make([]int64, 0)
	offsetValues := make([]int64, 0)

	for _, query := range queries {
		if query.LimitValue != nil {
			limitValues = append(limitValues, *query.LimitValue)
		}
		if query.OffsetValue != nil {
			offsetValues = append(offsetValues, *query.OffsetValue)
		}
	}

	// Check for consistent LIMIT (pagination pattern)
	if len(limitValues) > 0 {
		firstLimit := limitValues[0]
		consistentLimit := true
		for _, limit := range limitValues {
			if limit != firstLimit {
				consistentLimit = false
				break
			}
		}

		if consistentLimit && len(offsetValues) >= 3 {
			// Check for arithmetic progression in OFFSET values
			if pd.isArithmeticProgression(offsetValues, firstLimit) {
				return true
			}
		}
	}

	return false
}

// isArithmeticProgression checks if offset values form an arithmetic progression
func (pd *PatternDetector) isArithmeticProgression(offsets []int64, expectedStep int64) bool {
	if len(offsets) < 3 {
		return false
	}

	sort.Slice(offsets, func(i, j int) bool {
		return offsets[i] < offsets[j]
	})

	// Check if differences are consistent with LIMIT value
	tolerance := 0.8 // Allow some variance
	correctSteps := 0

	for i := 1; i < len(offsets); i++ {
		diff := offsets[i] - offsets[i-1]
		if float64(diff) >= float64(expectedStep)*tolerance &&
			float64(diff) <= float64(expectedStep)*(2.0-tolerance) {
			correctSteps++
		}
	}

	// At least 70% of steps should match expected progression
	return float64(correctSteps) >= float64(len(offsets)-1)*0.7
}

// detectRapidSequentialAccess detects rapid sequential access to same tables
func (pd *PatternDetector) detectRapidSequentialAccess(session *SessionTracker, analysis *PatternAnalysis) {
	recentQueries := pd.getRecentQueries(session.Queries, 5*time.Minute) // Shorter window for rapid access

	if len(recentQueries) < 10 { // Higher threshold for rapid access
		return
	}

	// Group by tables accessed (only LattIQ tables since we're already filtering)
	tableAccess := make(map[string]int)
	for _, query := range recentQueries {
		// Only count tables that are marked as LattIQ (since we're filtering at query level)
		if query.IsLattIQAccess {
			for _, table := range query.TablesAccessed {
				tableAccess[table]++
			}
		}
	}

	// Check for high frequency access to same tables
	for table, count := range tableAccess {
		if count >= 10 { // 10+ accesses to same table in 5 minutes
			analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns, "rapid_sequential_access")
			analysis.RiskScore += 30.0

			analysis.Details["rapid_access_table"] = table
			analysis.Details["access_count"] = count
			analysis.Details["access_rate"] = fmt.Sprintf("%.1f queries/minute", float64(count)/5.0)
		}
	}
}

// detectPaginationPatterns detects systematic pagination through large datasets
func (pd *PatternDetector) detectPaginationPatterns(session *SessionTracker, analysis *PatternAnalysis) {
	recentQueries := pd.getRecentQueries(session.Queries, pd.config.TimeWindow)

	paginationQueries := 0
	for _, query := range recentQueries {
		if query.HasLimit && query.HasOffset {
			paginationQueries++
		}
	}

	if paginationQueries >= pd.config.MinSimilarQueries {
		paginationRate := float64(paginationQueries) / float64(len(recentQueries))
		if paginationRate > 0.7 { // 70%+ of queries use pagination
			analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns, "systematic_pagination")
			analysis.RiskScore += 25.0

			analysis.Details["pagination_queries"] = paginationQueries
			analysis.Details["pagination_rate"] = fmt.Sprintf("%.1f%%", paginationRate*100)
		}
	}
}

// detectLattIQEnumeration detects systematic enumeration of LattIQ features
func (pd *PatternDetector) detectLattIQEnumeration(session *SessionTracker, analysis *PatternAnalysis) {
	recentQueries := pd.getRecentQueries(session.Queries, pd.config.TimeWindow)

	lattiqQueries := 0
	for _, query := range recentQueries {
		if query.IsLattIQAccess {
			lattiqQueries++
		}
	}

	if lattiqQueries >= 3 { // 3+ LattIQ feature accesses
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns, "lattiq_feature_enumeration")
		analysis.RiskScore += 50.0
		analysis.Confidence = 0.95

		analysis.Details["lattiq_queries"] = lattiqQueries
		analysis.Details["total_queries"] = len(recentQueries)
	}
}

// Helper functions

func (pd *PatternDetector) getOrCreateSession(sessionKey string, event *sentinelTypes.QueryLogEvent) *SessionTracker {
	if session, exists := pd.userSessions[sessionKey]; exists {
		return session
	}

	// Clean old sessions if we're at capacity
	if len(pd.userSessions) >= pd.config.MaxConcurrentSessions {
		pd.cleanOldSessions()
	}

	session := &SessionTracker{
		UserID:             event.UserName,
		ClientIP:           event.ClientIP,
		DatabaseName:       event.DatabaseName,
		Queries:            make([]QueryPattern, 0),
		FirstSeen:          time.UnixMilli(event.Timestamp),
		LastActivity:       time.UnixMilli(event.Timestamp),
		SuspiciousPatterns: make([]string, 0),
		RiskAccumulator:    0.0,
		AlertsTriggered:    make([]string, 0),
	}

	pd.userSessions[sessionKey] = session
	return session
}

func (pd *PatternDetector) getRecentQueries(queries []QueryPattern, window time.Duration) []QueryPattern {
	cutoff := time.Now().Add(-window)
	recent := make([]QueryPattern, 0)

	for _, query := range queries {
		if query.Timestamp.After(cutoff) {
			recent = append(recent, query)
		}
	}

	return recent
}

func (pd *PatternDetector) cleanOldSessions() {
	cutoff := time.Now().Add(-pd.config.MaxSessionInactivity)

	for key, session := range pd.userSessions {
		if session.LastActivity.Before(cutoff) {
			delete(pd.userSessions, key)
		}
	}
}

func (pd *PatternDetector) containsOrderBy(query string) bool {
	return regexp.MustCompile(`(?i)\bORDER\s+BY\b`).MatchString(query)
}

func (pd *PatternDetector) containsLimit(query string) bool {
	return regexp.MustCompile(`(?i)\bLIMIT\s+\d+`).MatchString(query)
}

func (pd *PatternDetector) containsOffset(query string) bool {
	return regexp.MustCompile(`(?i)\bOFFSET\s+\d+`).MatchString(query)
}

func (pd *PatternDetector) extractLimitValue(query string) *int64 {
	re := regexp.MustCompile(`(?i)\bLIMIT\s+(\d+)`)
	matches := re.FindStringSubmatch(query)
	if len(matches) >= 2 {
		if val, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			return &val
		}
	}
	return nil
}

func (pd *PatternDetector) extractOffsetValue(query string) *int64 {
	re := regexp.MustCompile(`(?i)\bOFFSET\s+(\d+)`)
	matches := re.FindStringSubmatch(query)
	if len(matches) >= 2 {
		if val, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			return &val
		}
	}
	return nil
}

// accessesConfiguredTables checks if the query accesses any configured LattIQ tables
func (pd *PatternDetector) accessesConfiguredTables(event *sentinelTypes.QueryLogEvent) bool {
	// If we have table access information, check for LattIQ tables
	if len(event.TableAccess) > 0 {
		for _, tableAccess := range event.TableAccess {
			if tableAccess.IsLattIQ {
				return true
			}
		}
	}

	// If no LattIQ tables found but we have a SELECT query with table access, still analyze it
	// This allows pattern detection even when table configuration might be incomplete
	if event.QueryType == "SELECT" && len(event.TableAccess) > 0 {
		return true
	}

	// If we have a SELECT query but no table access info, try to extract table names from the raw query
	// This is a fallback for when parsing didn't extract table access properly
	if event.QueryType == "SELECT" && event.RawQuery != "" {
		// Simple check for common table patterns in SELECT queries
		if strings.Contains(strings.ToUpper(event.RawQuery), "FROM") {
			return true
		}
	}

	return false
}
