# Sentinel - Data Abuse Monitoring Agent

<div align="center">

**A sophisticated monitoring agent for detecting unauthorized data usage and abuse in PostgreSQL databases**

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org/)
[![AWS SDK v2](https://img.shields.io/badge/AWS%20SDK-v2-orange.svg)](https://aws.amazon.com/sdk-for-go/)
[![Build Status](https://img.shields.io/badge/Build-Passing-green.svg)](#)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](#)

</div>

## 🚀 Overview

**Sentinel** is LattIQ's client-side monitoring agent designed to detect unauthorized usage, replication, and abuse of LattIQ's machine learning feature data within client PostgreSQL databases. The agent operates within client AWS infrastructure to provide real-time monitoring while maintaining data privacy and security.

### Key Capabilities

- **Real-time SQL Analysis**: Monitors PostgreSQL query logs for suspicious data access patterns
- **Systematic Attack Detection**: Advanced detection of ORDER BY pagination attacks and bulk extraction attempts
- **Infrastructure Monitoring**: Tracks RDS instances, replicas, snapshots, and configuration changes
- **Risk Scoring**: Sophisticated risk assessment combining multiple threat indicators
- **CloudTrail Integration**: Monitors AWS infrastructure operations for unauthorized database operations
- **Minimal Footprint**: Lightweight agent with <5% system impact

---

### Business Problem & Solution

For a detailed explanation of the business problem Sentinel addresses and its solution, please refer to the [Business Problem & Solution](docs/Business-Problem.md) document.

### Architecture

To understand the technical architecture of Sentinel, including its components and data flow, please refer to the [Architecture](docs/Architecture.md) document.

### Detection Capabilities

For detailed information about Sentinel's data sources, threat detection algorithms, risk scoring system, and alert thresholds, please refer to the [Detection Capabilities](docs/Detection-Capabilities.md) document.

## ⚙️ Configuration

### Environment Variables

```bash
# Client Configuration
export SENTINEL_CLIENT_ID="your-client-id"
export SENTINEL_CLIENT_NAME="Your Organization"
export SENTINEL_ENVIRONMENT="production"

# AWS Configuration
export AWS_REGION="us-east-1"
export RDS_INSTANCE_NAME="your-rds-instance"
export CLOUDTRAIL_S3_BUCKET="your-cloudtrail-bucket"
export AWS_ACCOUNT_ID="123456789012"

# Logging
export SENTINEL_LOG_LEVEL="info"
```

### Configuration File (`configs/sentinel.yaml`)

```yaml
client:
  id: "${SENTINEL_CLIENT_ID}"
  name: "${SENTINEL_CLIENT_NAME}"
  environment: "${SENTINEL_ENVIRONMENT:-production}"

hub:
  endpoint: "https://hub.lattiq.com/sentinel/api/v1/events/batch"
  secret_key: "your-hmac-secret-key"
  timeout: 30s
  compression: true

data_sources:
  query_logs:
    enabled: true
    log_group: "/aws/rds/instance/${RDS_INSTANCE_NAME}/postgresql"
    poll_interval: 30s
    batch_size: 100
    log_format:
      log_line_prefix: "%t:%r:%u@%d:[%p]:"
      auto_detect: true

  rds:
    enabled: true
    instances: ["${RDS_INSTANCE_NAME}"]
    poll_intervals:
      instances: 15m
      config: 30m
      snapshots: 30m

  cloudtrail:
    enabled: true
    s3_bucket: "${CLOUDTRAIL_S3_BUCKET}"
    s3_prefix: "AWSLogs/${AWS_ACCOUNT_ID}/CloudTrail/${AWS_REGION}/"
    event_names:
      - "CreateDBSnapshot"
      - "RestoreDBInstanceFromDBSnapshot"
      - "CreateDBInstanceReadReplica"
    poll_interval: 5m

features:
  tables:
    customers:
      database: "production_db"
      schema: "public"
      lattiq_columns:
        - "risk_score"
        - "churn_probability"
        - "fraud_indicator"
        - "lifetime_value_score"
      primary_key: ["customer_id"]
      description: "Customer master table with LattIQ ML features"

    transactions:
      database: "production_db"
      schema: "public"
      lattiq_columns:
        - "anomaly_score"
        - "risk_category"
      primary_key: ["transaction_id"]
      description: "Transaction table with LattIQ risk features"

batch:
  max_size: 100
  max_age: 30s
  compression: true

health:
  enabled: true
  report_interval: 5m
```

---

## 🛠️ Installation & Deployment

### Prerequisites

- **Go 1.22+** for building from source
- **AWS Credentials** with appropriate permissions
- **PostgreSQL** with query logging enabled (`log_statement = 'all'`)
- **CloudWatch Logs** integration for PostgreSQL logs

### Production Deployment

#### 1. **AWS IAM Permissions**

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
      "Resource": "arn:aws:s3:::cloudtrail-bucket/*"
    }
  ]
}
```

#### 2. **PostgreSQL Configuration**

```sql
-- Required settings for monitoring
log_statement = 'all'
log_duration = on
log_connections = on
log_disconnections = on
log_temp_files = 0  -- Critical: Detects bulk operations
log_lock_waits = on -- Useful: Concurrent access patterns
log_line_prefix = '%t:%r:%u@%d:[%p]:'
```

#### 3. **CloudWatch Integration**

Ensure PostgreSQL logs are streamed to CloudWatch via RDS configuration.
