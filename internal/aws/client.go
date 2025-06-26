package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"

	sentinelConfig "github.com/lattiq/sentinel/internal/config"
)

// ClientManager manages AWS service clients
type ClientManager struct {
	config    *sentinelConfig.Config
	awsConfig aws.Config
	logger    *logrus.Entry

	// Service clients (lazy loaded)
	cwLogs *cloudwatchlogs.Client
	rds    *rds.Client
	s3     *s3.Client
}

// NewClientManager creates a new AWS client manager
func NewClientManager(cfg *sentinelConfig.Config) (*ClientManager, error) {
	logger := logrus.WithField("component", "aws_client_manager")

	// Load AWS configuration
	awsConfig, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.AWS.Region),
		config.WithSharedConfigProfile(cfg.AWS.Profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	manager := &ClientManager{
		config:    cfg,
		awsConfig: awsConfig,
		logger:    logger,
	}

	logger.WithFields(logrus.Fields{
		"region":  cfg.AWS.Region,
		"profile": cfg.AWS.Profile,
	}).Info("AWS client manager initialized")

	return manager, nil
}

// CloudWatchLogs returns a CloudWatch Logs client (lazy loaded)
func (m *ClientManager) CloudWatchLogs() *cloudwatchlogs.Client {
	if m.cwLogs == nil {
		m.cwLogs = cloudwatchlogs.NewFromConfig(m.awsConfig)
		m.logger.Debug("CloudWatch Logs client created")
	}
	return m.cwLogs
}

// RDS returns an RDS client (lazy loaded)
func (m *ClientManager) RDS() *rds.Client {
	if m.rds == nil {
		m.rds = rds.NewFromConfig(m.awsConfig)
		m.logger.Debug("RDS client created")
	}
	return m.rds
}

// GetRDSClient returns an RDS client (alias for compatibility)
func (m *ClientManager) GetRDSClient() (*rds.Client, error) {
	return m.RDS(), nil
}

// S3 returns an S3 client (lazy loaded)
func (m *ClientManager) S3() *s3.Client {
	if m.s3 == nil {
		m.s3 = s3.NewFromConfig(m.awsConfig)
		m.logger.Debug("S3 client created")
	}
	return m.s3
}

// ValidatePermissions validates that the AWS credentials have the required permissions
func (m *ClientManager) ValidatePermissions(ctx context.Context) error {
	m.logger.Info("Validating AWS permissions...")

	// Test CloudWatch Logs permissions
	if m.config.DataSources.QueryLogs.Enabled {
		if err := m.validateCloudWatchLogsPermissions(ctx); err != nil {
			return fmt.Errorf("CloudWatch Logs permissions validation failed: %w", err)
		}
	}

	// Test RDS permissions
	if m.config.DataSources.RDS.Enabled {
		if err := m.validateRDSPermissions(ctx); err != nil {
			return fmt.Errorf("RDS permissions validation failed: %w", err)
		}
	}

	// Test S3 permissions (if CloudTrail uses S3)
	if m.config.DataSources.CloudTrail.Enabled && m.config.DataSources.CloudTrail.S3Bucket != "" {
		if err := m.validateS3Permissions(ctx); err != nil {
			return fmt.Errorf("S3 permissions validation failed: %w", err)
		}
	}

	m.logger.Info("AWS permissions validation completed successfully")
	return nil
}

// validateCloudWatchLogsPermissions validates CloudWatch Logs access
func (m *ClientManager) validateCloudWatchLogsPermissions(ctx context.Context) error {
	client := m.CloudWatchLogs()

	// Try to describe log groups (read-only operation)
	input := &cloudwatchlogs.DescribeLogGroupsInput{
		Limit: aws.Int32(1),
	}

	_, err := client.DescribeLogGroups(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe log groups: %w", err)
	}

	m.logger.Debug("CloudWatch Logs permissions validated")
	return nil
}

// validateRDSPermissions validates RDS API access
func (m *ClientManager) validateRDSPermissions(ctx context.Context) error {
	client := m.RDS()

	// If we have specific instances configured, validate access to all of them
	if len(m.config.DataSources.RDS.Instances) > 0 {
		for _, instanceID := range m.config.DataSources.RDS.Instances {
			input := &rds.DescribeDBInstancesInput{
				DBInstanceIdentifier: aws.String(instanceID),
			}

			_, err := client.DescribeDBInstances(ctx, input)
			if err != nil {
				return fmt.Errorf("failed to describe configured DB instance %s: %w", instanceID, err)
			}
			m.logger.WithField("instance_id", instanceID).Debug("RDS instance access validated")
		}
	} else {
		// Fallback to describing all instances (for monitor_all_instances mode)
		input := &rds.DescribeDBInstancesInput{
			MaxRecords: aws.Int32(20),
		}

		_, err := client.DescribeDBInstances(ctx, input)
		if err != nil {
			return fmt.Errorf("failed to describe DB instances: %w", err)
		}
	}

	m.logger.Debug("RDS permissions validated")
	return nil
}

// validateS3Permissions validates S3 bucket access
func (m *ClientManager) validateS3Permissions(ctx context.Context) error {
	client := m.S3()
	bucket := m.config.DataSources.CloudTrail.S3Bucket

	// Try to list objects in the bucket (read-only operation)
	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		MaxKeys: aws.Int32(1),
	}

	_, err := client.ListObjectsV2(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to list objects in bucket %s: %w", bucket, err)
	}

	m.logger.Debug("S3 permissions validated")
	return nil
}

// GetRegion returns the configured AWS region
func (m *ClientManager) GetRegion() string {
	return m.config.AWS.Region
}

// Health returns the health status of the AWS client manager
func (m *ClientManager) Health(ctx context.Context) error {
	// Quick health check - validate permissions
	return m.ValidatePermissions(ctx)
}
