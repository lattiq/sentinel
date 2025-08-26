package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/lattiq/sentinel/internal/agent"
	"github.com/lattiq/sentinel/internal/config"
	"github.com/lattiq/sentinel/version"
)

func main() {
	var (
		configFile  = flag.String("config", "sentinel.yaml", "Path to configuration file")
		showVersion = flag.Bool("version", false, "Show version information")
		debug       = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("Sentinel Agent v%s\n", version.Version())
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Override log level if debug flag is set
	if *debug {
		cfg.Logging.Level = "debug"
	}

	// Setup logging
	setupLogging(cfg.Logging)

	logger := logrus.WithFields(logrus.Fields{
		"version": version.Version(),
		"client":  cfg.Client.ID,
	})

	logger.Info("Starting Sentinel Agent")

	// Create agent
	sentinelAgent, err := agent.New(cfg)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create agent")
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start agent
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sentinelAgent.Start(); err != nil {
			logger.WithError(err).Error("Agent failed to start")
			cancel()
		}
	}()

	// Wait for shutdown signal
	select {
	case sig := <-sigChan:
		logger.WithField("signal", sig.String()).Info("Received shutdown signal")
		cancel()
	case <-ctx.Done():
		logger.Info("Context cancelled")
	}

	// Graceful shutdown
	logger.Info("Shutting down Sentinel Agent")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := sentinelAgent.Stop(); err != nil {
		logger.WithError(err).Error("Error during shutdown")
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Sentinel Agent stopped successfully")
	case <-shutdownCtx.Done():
		logger.Warn("Shutdown timeout reached, forcing exit")
	}
}

func setupLogging(cfg config.LoggingConfig) {
	// Set log level
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	// Set log format
	if cfg.Format == "json" {
		logrus.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	}

	// Set output
	if cfg.File != "" {
		// TODO: Implement log rotation
		file, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logrus.WithError(err).Warn("Failed to open log file, using stdout")
		} else {
			logrus.SetOutput(file)
		}
	}
}
