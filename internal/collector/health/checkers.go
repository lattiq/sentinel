package health

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	awsClient "github.com/lattiq/sentinel/internal/aws"
	"github.com/lattiq/sentinel/internal/config"
	sentinelTypes "github.com/lattiq/sentinel/pkg/types"
)

// RDSHealthChecker monitors RDS service health
type RDSHealthChecker struct {
	config     *config.Config
	awsManager *awsClient.ClientManager
}

// NewRDSHealthChecker creates a new RDS health checker
func NewRDSHealthChecker(cfg *config.Config, awsManager *awsClient.ClientManager) *RDSHealthChecker {
	return &RDSHealthChecker{
		config:     cfg,
		awsManager: awsManager,
	}
}

// Name returns the checker name
func (c *RDSHealthChecker) Name() string {
	return "rds"
}

// Check performs RDS health check
func (c *RDSHealthChecker) Check(ctx context.Context) *sentinelTypes.HealthEvent {
	startTime := time.Now()
	status := "healthy"
	var lastError string
	var errorCount int64

	// Test RDS connectivity
	rdsClient, err := c.awsManager.GetRDSClient()
	if err != nil {
		status = "unhealthy"
		lastError = fmt.Sprintf("Failed to get RDS client: %v", err)
		errorCount++
	} else {
		// Test basic RDS functionality
		if len(c.config.DataSources.RDS.Instances) > 0 {
			// Test access to all configured instances
			for _, instanceID := range c.config.DataSources.RDS.Instances {
				_, err = rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
					DBInstanceIdentifier: aws.String(instanceID),
				})
				if err != nil {
					status = "degraded"
					lastError = fmt.Sprintf("Failed to describe configured RDS instance %s: %v", instanceID, err)
					errorCount++
					break // Stop on first failure to avoid overwhelming logs
				}
			}
		} else {
			// Fallback to describing all instances (for monitor_all_instances mode)
			_, err = rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
				MaxRecords: aws.Int32(20),
			})
			if err != nil {
				status = "degraded"
				lastError = fmt.Sprintf("Failed to describe RDS instances: %v", err)
				errorCount++
			}
		}
	}

	// Additional metrics
	metrics := map[string]interface{}{
		"response_time_ms":    time.Since(startTime).Milliseconds(),
		"monitored_instances": len(c.config.DataSources.RDS.Instances),
		"monitor_all":         c.config.DataSources.RDS.MonitorAllInstances,
		"region":              c.config.AWS.Region,
	}

	return &sentinelTypes.HealthEvent{
		ComponentName: "rds",
		Status:        status,
		Timestamp:     time.Now().Unix(),
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		ErrorCount:    errorCount,
		LastError:     lastError,
		Metrics:       metrics,
	}
}

// CloudWatchHealthChecker monitors CloudWatch Logs service health
type CloudWatchHealthChecker struct {
	config     *config.Config
	awsManager *awsClient.ClientManager
}

// NewCloudWatchHealthChecker creates a new CloudWatch health checker
func NewCloudWatchHealthChecker(cfg *config.Config, awsManager *awsClient.ClientManager) *CloudWatchHealthChecker {
	return &CloudWatchHealthChecker{
		config:     cfg,
		awsManager: awsManager,
	}
}

// Name returns the checker name
func (c *CloudWatchHealthChecker) Name() string {
	return "cloudwatch"
}

// Check performs CloudWatch health check
func (c *CloudWatchHealthChecker) Check(ctx context.Context) *sentinelTypes.HealthEvent {
	startTime := time.Now()
	status := "healthy"
	var lastError string
	var errorCount int64

	// Test CloudWatch Logs connectivity
	cwLogsClient := c.awsManager.CloudWatchLogs()
	if cwLogsClient == nil {
		status = "unhealthy"
		lastError = "Failed to get CloudWatch Logs client"
		errorCount++
	} else {
		// Test basic CloudWatch functionality
		_, err := cwLogsClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			Limit: aws.Int32(1),
		})
		if err != nil {
			status = "degraded"
			lastError = fmt.Sprintf("Failed to describe log groups: %v", err)
			errorCount++
		}

		// Test specific log group access if configured
		if c.config.DataSources.QueryLogs.LogGroup != "" {
			_, err = cwLogsClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
				LogGroupNamePrefix: aws.String(c.config.DataSources.QueryLogs.LogGroup),
			})
			if err != nil {
				status = "degraded"
				lastError = fmt.Sprintf("Failed to access configured log group: %v", err)
				errorCount++
			}
		}
	}

	// Additional metrics
	metrics := map[string]interface{}{
		"response_time_ms": time.Since(startTime).Milliseconds(),
		"log_group":        c.config.DataSources.QueryLogs.LogGroup,
		"poll_interval":    c.config.DataSources.QueryLogs.PollInterval.String(),
		"batch_size":       c.config.DataSources.QueryLogs.BatchSize,
		"region":           c.config.AWS.Region,
	}

	return &sentinelTypes.HealthEvent{
		ComponentName: "cloudwatch",
		Status:        status,
		Timestamp:     time.Now().Unix(),
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		ErrorCount:    errorCount,
		LastError:     lastError,
		Metrics:       metrics,
	}
}

// S3HealthChecker monitors S3 service health
type S3HealthChecker struct {
	config     *config.Config
	awsManager *awsClient.ClientManager
}

// NewS3HealthChecker creates a new S3 health checker
func NewS3HealthChecker(cfg *config.Config, awsManager *awsClient.ClientManager) *S3HealthChecker {
	return &S3HealthChecker{
		config:     cfg,
		awsManager: awsManager,
	}
}

// Name returns the checker name
func (c *S3HealthChecker) Name() string {
	return "s3"
}

// Check performs S3 health check
func (c *S3HealthChecker) Check(ctx context.Context) *sentinelTypes.HealthEvent {
	startTime := time.Now()
	status := "healthy"
	var lastError string
	var errorCount int64

	// Test S3 connectivity
	s3Client := c.awsManager.S3()
	if s3Client == nil {
		status = "unhealthy"
		lastError = "Failed to get S3 client"
		errorCount++
	} else {
		// Test bucket access
		bucketName := c.config.DataSources.CloudTrail.S3Bucket
		if bucketName != "" {
			_, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				status = "degraded"
				lastError = fmt.Sprintf("Failed to access S3 bucket %s: %v", bucketName, err)
				errorCount++
			} else {
				// Test listing objects in bucket
				_, err = s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
					Bucket:  aws.String(bucketName),
					Prefix:  aws.String(c.config.DataSources.CloudTrail.S3Prefix),
					MaxKeys: aws.Int32(1),
				})
				if err != nil {
					status = "degraded"
					lastError = fmt.Sprintf("Failed to list objects in S3 bucket: %v", err)
					errorCount++
				}
			}
		}
	}

	// Additional metrics
	metrics := map[string]interface{}{
		"response_time_ms": time.Since(startTime).Milliseconds(),
		"bucket_name":      c.config.DataSources.CloudTrail.S3Bucket,
		"prefix":           c.config.DataSources.CloudTrail.S3Prefix,
		"poll_interval":    c.config.DataSources.CloudTrail.PollInterval.String(),
		"region":           c.config.AWS.Region,
	}

	return &sentinelTypes.HealthEvent{
		ComponentName: "s3",
		Status:        status,
		Timestamp:     time.Now().Unix(),
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		ErrorCount:    errorCount,
		LastError:     lastError,
		Metrics:       metrics,
	}
}

// WatchtowerHealthChecker monitors Watchtower service health
type WatchtowerHealthChecker struct {
	config *config.Config
	client *http.Client
}

// NewWatchtowerHealthChecker creates a new Watchtower health checker
func NewWatchtowerHealthChecker(cfg *config.Config) *WatchtowerHealthChecker {
	return &WatchtowerHealthChecker{
		config: cfg,
		client: &http.Client{
			Timeout: cfg.Watchtower.Timeout,
		},
	}
}

// Name returns the checker name
func (c *WatchtowerHealthChecker) Name() string {
	return "watchtower"
}

// Check performs Watchtower health check
func (c *WatchtowerHealthChecker) Check(ctx context.Context) *sentinelTypes.HealthEvent {
	startTime := time.Now()
	status := "healthy"
	var lastError string
	var errorCount int64

	// Test Watchtower connectivity
	endpoint := c.config.Watchtower.Endpoint
	if endpoint != "" {
		// Create a simple GET request to check connectivity
		req, err := http.NewRequestWithContext(ctx, "GET", path.Join(endpoint, "/watchtower/health"), nil)
		if err != nil {
			status = "unhealthy"
			lastError = fmt.Sprintf("Failed to create request: %v", err)
			errorCount++
		} else {
			resp, err := c.client.Do(req)
			if err != nil {
				status = "degraded"
				lastError = fmt.Sprintf("Failed to connect to watchtower: %v", err)
				errorCount++
			} else {
				resp.Body.Close()
				// Accept any response code as "reachable"
				// The actual health check would depend on specific endpoint behavior
				if resp.StatusCode >= 500 {
					status = "degraded"
					lastError = fmt.Sprintf("Watchtower returned server error: %d", resp.StatusCode)
					errorCount++
				}
			}
		}
	} else {
		status = "unknown"
		lastError = "No watchtower endpoint configured"
	}

	// Additional metrics
	metrics := map[string]interface{}{
		"response_time_ms": time.Since(startTime).Milliseconds(),
		"endpoint":         endpoint,
		"client_id":        c.config.Client.ID,
		"timeout":          c.config.Watchtower.Timeout.String(),
		"compression":      c.config.Watchtower.Compression,
	}

	return &sentinelTypes.HealthEvent{
		ComponentName: "watchtower",
		Status:        status,
		Timestamp:     time.Now().Unix(),
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		ErrorCount:    errorCount,
		LastError:     lastError,
		Metrics:       metrics,
	}
}
