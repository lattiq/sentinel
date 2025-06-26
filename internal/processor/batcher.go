package processor

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/pkg/types"
)

// Batcher handles batching of monitoring messages
type Batcher struct {
	config *config.BatchConfig
	logger *logrus.Entry

	mu           sync.Mutex
	currentBatch []types.MonitoringMessage
	batchTimer   *time.Timer
	outputChan   chan []types.MonitoringMessage

	// Metrics
	totalBatches     int64
	totalMessages    int64
	avgBatchSize     float64
	avgBatchAge      float64
	compressionRatio float64
}

// NewBatcher creates a new message batcher
func NewBatcher(config *config.BatchConfig, logger *logrus.Entry) *Batcher {
	return &Batcher{
		config:       config,
		logger:       logger.WithField("component", "batcher"),
		currentBatch: make([]types.MonitoringMessage, 0, config.MaxSize),
		outputChan:   make(chan []types.MonitoringMessage, 100),
	}
}

// Start begins the batching process
func (b *Batcher) Start(ctx context.Context) error {
	b.logger.Info("Starting message batcher")

	// Start the batch timer
	b.resetBatchTimer()

	// Start batch processing goroutine
	go b.processBatches(ctx)

	return nil
}

// Stop stops the batching process
func (b *Batcher) Stop(ctx context.Context) error {
	b.logger.Info("Stopping message batcher")

	b.mu.Lock()
	defer b.mu.Unlock()

	// Flush any remaining messages
	if len(b.currentBatch) > 0 {
		b.flushBatch()
	}

	// Stop timer
	if b.batchTimer != nil {
		b.batchTimer.Stop()
	}

	// Close output channel
	close(b.outputChan)

	return nil
}

// AddMessage adds a message to the current batch
func (b *Batcher) AddMessage(message types.MonitoringMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.currentBatch = append(b.currentBatch, message)

	// Check if batch is full
	if len(b.currentBatch) >= b.config.MaxSize {
		b.flushBatch()
	}
}

// AddMessages adds multiple messages to the current batch
func (b *Batcher) AddMessages(messages []types.MonitoringMessage) {
	for _, message := range messages {
		b.AddMessage(message)
	}
}

// GetOutputChannel returns the channel for receiving batched messages
func (b *Batcher) GetOutputChannel() <-chan []types.MonitoringMessage {
	return b.outputChan
}

// flushBatch sends the current batch and resets it (must be called with lock held)
func (b *Batcher) flushBatch() {
	if len(b.currentBatch) == 0 {
		return
	}

	batch := make([]types.MonitoringMessage, len(b.currentBatch))
	copy(batch, b.currentBatch)

	// Update batch metadata
	batchSize := len(batch)
	for i := range batch {
		batch[i].BatchSize = batchSize
	}

	// Send batch
	select {
	case b.outputChan <- batch:
		b.logger.WithField("batch_size", batchSize).Debug("Batch flushed")
	default:
		b.logger.Warn("Output channel full, dropping batch")
	}

	// Update metrics
	b.updateMetrics(batch)

	// Reset batch
	b.currentBatch = b.currentBatch[:0]
	b.resetBatchTimer()
}

// resetBatchTimer resets the batch timer (must be called with lock held)
func (b *Batcher) resetBatchTimer() {
	if b.batchTimer != nil {
		b.batchTimer.Stop()
	}

	b.batchTimer = time.AfterFunc(b.config.MaxAge, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.flushBatch()
	})
}

// processBatches handles the batch processing loop
func (b *Batcher) processBatches(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			b.logger.Info("Batch processing stopped")
			return
		default:
			// The actual batching is handled by AddMessage and the timer
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// updateMetrics updates batching metrics
func (b *Batcher) updateMetrics(batch []types.MonitoringMessage) {
	b.totalBatches++
	b.totalMessages += int64(len(batch))

	// Update average batch size
	b.avgBatchSize = float64(b.totalMessages) / float64(b.totalBatches)

	// Calculate batch age (simplified - using current time)
	now := time.Now()
	var totalAge time.Duration
	for _, msg := range batch {
		msgTime := time.Unix(msg.Timestamp, 0)
		totalAge += now.Sub(msgTime)
	}

	if len(batch) > 0 {
		avgAge := totalAge / time.Duration(len(batch))
		b.avgBatchAge = float64(avgAge.Milliseconds())
	}

	b.logger.WithFields(logrus.Fields{
		"total_batches":  b.totalBatches,
		"total_messages": b.totalMessages,
		"avg_batch_size": b.avgBatchSize,
		"avg_batch_age":  b.avgBatchAge,
	}).Debug("Batch metrics updated")
}

// GetMetrics returns batching metrics
func (b *Batcher) GetMetrics() types.BatchMetrics {
	b.mu.Lock()
	defer b.mu.Unlock()

	return types.BatchMetrics{
		TotalBatches:     b.totalBatches,
		AvgBatchSize:     b.avgBatchSize,
		AvgBatchAge:      b.avgBatchAge,
		CompressionRatio: b.compressionRatio,
	}
}
