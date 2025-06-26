# 📊 Data Sources & Detection Capabilities

## Data Sources Monitored

### 1. PostgreSQL Query Logs (Primary Source)

- **Purpose**: Real-time SQL-level abuse detection
- **Source**: PostgreSQL logs with `log_statement = 'all'` streaming to CloudWatch
- **Freshness**: Near real-time (1-2 minute delay)
- **Key Data**: Query text, duration, user, IP, rows affected, temp files

### 2. AWS RDS API - Database Instances

- **Purpose**: Infrastructure-level replica and restore detection
- **Polling**: Every 15 minutes
- **Detects**: Read replicas, restore operations, configuration changes

### 3. AWS RDS API - Configuration Parameters

- **Purpose**: Monitor replication-enabling settings
- **Polling**: Every 30 minutes
- **Monitors**: `wal_level`, `max_replication_slots`, `archive_mode`

### 4. AWS RDS API - Snapshots

- **Purpose**: Backup anomaly detection
- **Polling**: Every 30 minutes
- **Detects**: Manual snapshots, unusual backup patterns

### 5. AWS CloudTrail Events

- **Purpose**: Real-time infrastructure operations
- **Freshness**: Real-time event streaming
- **Key Events**: `CreateDBSnapshot`, `RestoreDBInstance*`, `CreateDBInstanceReadReplica`

## 🔍 Advanced Threat Detection

### 1. **🚨 Systematic ORDER BY Extraction Detection**

**The Problem**: Attackers use systematic ORDER BY queries in loops to extract data in small chunks, avoiding traditional bulk operation detection.

**Sentinel's Detection Capabilities**:

- **Query Pattern Normalization**: Identifies similar queries with variable OFFSET/LIMIT values
- **Arithmetic Progression Detection**: Recognizes systematic progression (0, 1000, 2000, 3000...)
- **Session Correlation**: Tracks patterns across user sessions (User + IP + Database)
- **Time Window Analysis**: Monitors within 15-minute configurable windows

### 2. **LattIQ Feature Access Monitoring**

- **Column-Level Tracking**: Monitors access to specific ML feature columns
- **Risk Scoring**: +30 base score for any LattIQ feature access
- **Table Mapping**: Configurable feature column identification
- **Multi-Table Support**: Tracks features across multiple database tables

### 3. **Bulk Data Operations**

- **Temporary File Detection**: +35 risk score for bulk operations
- **Long-Running Queries**: +20 (>30s), +40 (>5min) risk escalation
- **COPY Operations**: +25 base score for data export attempts
- **Row Count Analysis**: +30 for operations affecting >10,000 rows

### 4. **Infrastructure Monitoring**

- **Read Replica Detection**: Real-time monitoring of database replicas
- **Snapshot Tracking**: Monitors backup creation and restoration
- **Configuration Changes**: Tracks replication-enabling parameter modifications
- **CloudTrail Integration**: Real-time AWS API operation monitoring

## 📈 Risk Scoring System

| Activity Type               | Base Risk Score | Escalation Triggers                |
| --------------------------- | --------------- | ---------------------------------- |
| SELECT queries              | +10             | +20 if >30s duration               |
| LattIQ feature access       | +30             | +50 if bulk operation              |
| Temporary file creation     | +35             | +20 if >1GB file                   |
| Replication activity        | +50             | Immediate high-priority alert      |
| COPY operations             | +25             | +30 if to external location        |
| **Systematic ORDER BY**     | **+60**         | **+40 if LattIQ features**         |
| **Rapid sequential access** | **+30**         | **10+ queries/5min to same table** |
| **Systematic pagination**   | **+25**         | **70%+ queries use LIMIT/OFFSET**  |

## Alert Thresholds

### 🚨 High-Priority Alerts (Risk Score 60+)

- **Systematic ORDER BY extraction** (Risk Score 60-100+)
- Replication slot creation or logical replication commands
- Bulk data extraction with temporary files >1GB
- Extremely long queries (>5 minutes)
- Multiple LattIQ table access in single session

### ⚠️ Medium-Priority Alerts (Risk Score 30-59)

- **Rapid sequential access** (10+ queries/5min to same table)
- **Systematic pagination patterns** (70%+ queries use LIMIT/OFFSET)
- Long-running queries (30s-5min)
- COPY operations to external destinations
- Unusual access patterns (new IPs, off-hours access)

### ℹ️ Informational Monitoring (Risk Score <30)

- Normal query patterns
- Connection/disconnection events
- Lock wait events
- Standard LattIQ feature access
