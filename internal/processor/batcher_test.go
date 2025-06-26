package processor

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/pkg/types"
)

func TestNewBatcher(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	config := &config.BatchConfig{
		MaxSize: 50,
		MaxAge:  10 * time.Second,
	}

	batcher := NewBatcher(config, logger)
	assert.NotNil(t, batcher)
	assert.Equal(t, config, batcher.config)
	assert.NotNil(t, batcher.logger)
	assert.NotNil(t, batcher.outputChan)
}

func TestBatcher_AddMessage(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	config := &config.BatchConfig{
		MaxSize: 3, // Small batch size for testing
		MaxAge:  1 * time.Second,
	}

	batcher := NewBatcher(config, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := batcher.Start(ctx)
	require.NoError(t, err)

	// Create test messages
	messages := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
		createTestMonitoringMessage("msg2"),
		createTestMonitoringMessage("msg3"),
	}

	// Add messages one by one
	for _, msg := range messages {
		batcher.AddMessage(msg)
	}

	// Should receive a batch when max size is reached
	select {
	case batch := <-batcher.GetOutputChannel():
		assert.Len(t, batch, 3)
		for i, msg := range batch {
			assert.Equal(t, messages[i].MessageID, msg.MessageID)
			assert.Equal(t, 3, msg.BatchSize) // Batch size should be updated
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Expected to receive a batch within timeout")
	}

	err = batcher.Stop(ctx)
	assert.NoError(t, err)
}

func TestBatcher_AddMessages(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	config := &config.BatchConfig{
		MaxSize: 5,
		MaxAge:  1 * time.Second,
	}

	batcher := NewBatcher(config, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := batcher.Start(ctx)
	require.NoError(t, err)

	// Create test messages
	messages := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
		createTestMonitoringMessage("msg2"),
		createTestMonitoringMessage("msg3"),
	}

	// Add multiple messages at once
	batcher.AddMessages(messages)

	// Add more messages to trigger batch
	batcher.AddMessage(createTestMonitoringMessage("msg4"))
	batcher.AddMessage(createTestMonitoringMessage("msg5"))

	// Should receive a batch when max size is reached
	select {
	case batch := <-batcher.GetOutputChannel():
		assert.Len(t, batch, 5)
		assert.Equal(t, 5, batch[0].BatchSize)
	case <-time.After(2 * time.Second):
		t.Fatal("Expected to receive a batch within timeout")
	}

	err = batcher.Stop(ctx)
	assert.NoError(t, err)
}

func TestBatcher_TimeBasedBatching(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	config := &config.BatchConfig{
		MaxSize: 100,                    // Large batch size
		MaxAge:  500 * time.Millisecond, // Short timeout for testing
	}

	batcher := NewBatcher(config, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := batcher.Start(ctx)
	require.NoError(t, err)

	// Add a few messages (less than max size)
	messages := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
		createTestMonitoringMessage("msg2"),
	}

	batcher.AddMessages(messages)

	// Should receive a batch after timeout
	select {
	case batch := <-batcher.GetOutputChannel():
		assert.Len(t, batch, 2)
		assert.Equal(t, 2, batch[0].BatchSize)
	case <-time.After(1 * time.Second):
		t.Fatal("Expected to receive a batch within timeout")
	}

	err = batcher.Stop(ctx)
	assert.NoError(t, err)
}

func TestBatcher_GetMetrics(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	config := &config.BatchConfig{
		MaxSize: 2,
		MaxAge:  1 * time.Second,
	}

	batcher := NewBatcher(config, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := batcher.Start(ctx)
	require.NoError(t, err)

	// Add messages to trigger batching
	messages := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
		createTestMonitoringMessage("msg2"),
	}

	batcher.AddMessages(messages)

	// Wait for batch to be processed
	select {
	case <-batcher.GetOutputChannel():
		// Batch received
	case <-time.After(2 * time.Second):
		t.Fatal("Expected to receive a batch within timeout")
	}

	// Check metrics
	metrics := batcher.GetMetrics()
	assert.Equal(t, int64(1), metrics.TotalBatches)
	assert.Equal(t, float64(2), metrics.AvgBatchSize)
	assert.Greater(t, metrics.AvgBatchAge, 0.0)

	err = batcher.Stop(ctx)
	assert.NoError(t, err)
}

func TestBatcher_MultipleBatches(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	config := &config.BatchConfig{
		MaxSize: 2,
		MaxAge:  1 * time.Second,
	}

	batcher := NewBatcher(config, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := batcher.Start(ctx)
	require.NoError(t, err)

	// Send multiple batches
	for i := 0; i < 3; i++ {
		messages := []types.MonitoringMessage{
			createTestMonitoringMessage("msg1"),
			createTestMonitoringMessage("msg2"),
		}
		batcher.AddMessages(messages)

		// Wait for batch
		select {
		case batch := <-batcher.GetOutputChannel():
			assert.Len(t, batch, 2)
		case <-time.After(2 * time.Second):
			t.Fatal("Expected to receive a batch within timeout")
		}
	}

	// Check metrics after multiple batches
	metrics := batcher.GetMetrics()
	assert.Equal(t, int64(3), metrics.TotalBatches)
	assert.Equal(t, float64(2), metrics.AvgBatchSize)

	err = batcher.Stop(ctx)
	assert.NoError(t, err)
}

func TestBatcher_StopWithPendingMessages(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	config := &config.BatchConfig{
		MaxSize: 100,              // Large batch size
		MaxAge:  10 * time.Second, // Long timeout
	}

	batcher := NewBatcher(config, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := batcher.Start(ctx)
	require.NoError(t, err)

	// Add messages but don't reach batch size
	messages := []types.MonitoringMessage{
		createTestMonitoringMessage("msg1"),
		createTestMonitoringMessage("msg2"),
	}

	batcher.AddMessages(messages)

	// Stop batcher - should flush pending messages
	err = batcher.Stop(ctx)
	assert.NoError(t, err)

	// Should receive the pending batch
	select {
	case batch := <-batcher.GetOutputChannel():
		assert.Len(t, batch, 2)
	case <-time.After(1 * time.Second):
		t.Fatal("Expected to receive pending batch within timeout")
	}
}

func TestBatcher_ConcurrentAccess(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	config := &config.BatchConfig{
		MaxSize: 10,
		MaxAge:  1 * time.Second,
	}

	batcher := NewBatcher(config, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := batcher.Start(ctx)
	require.NoError(t, err)

	// Add messages concurrently from multiple goroutines
	done := make(chan bool)
	numGoroutines := 5
	messagesPerGoroutine := 4

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < messagesPerGoroutine; j++ {
				msg := createTestMonitoringMessage("msg-" + string(rune(id)) + "-" + string(rune(j)))
				batcher.AddMessage(msg)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Collect all batches
	totalMessages := 0
	timeout := time.After(3 * time.Second)

	for totalMessages < numGoroutines*messagesPerGoroutine {
		select {
		case batch := <-batcher.GetOutputChannel():
			totalMessages += len(batch)
		case <-timeout:
			// Stop and flush remaining
			err = batcher.Stop(ctx)
			assert.NoError(t, err)

			// Try to get final batch
			select {
			case batch := <-batcher.GetOutputChannel():
				totalMessages += len(batch)
			default:
				// No more batches
			}
			break
		}
	}

	assert.Equal(t, numGoroutines*messagesPerGoroutine, totalMessages)
}

// Helper function
func createTestMonitoringMessage(id string) types.MonitoringMessage {
	return types.MonitoringMessage{
		MessageID:   id,
		ClientID:    "test-client",
		Timestamp:   time.Now().Unix(),
		MessageType: types.MessageTypeQueryLogs,
		BatchSize:   1,
		Data:        map[string]interface{}{"test": "data"},
		Version:     "1.0",
	}
}
