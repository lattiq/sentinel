// Example demonstrating how to use the Sentinel transmitter to send batch events
// with HMAC authentication to the LattIQ Watchtower
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/lattiq/sentinel/internal/hmac"
	"github.com/lattiq/sentinel/pkg/types"
	"github.com/lattiq/sentinel/version"
)

func main() {
	fmt.Println("Sentinel Transmitter Example")
	fmt.Println("===========================")
	fmt.Println()

	fmt.Println("This example demonstrates:")
	fmt.Println("1. Creating a sample monitoring message")
	fmt.Println("2. Generating HMAC-SHA256 signature")
	fmt.Println("3. Sending to LattIQ Watchtower using resty HTTP client")
	fmt.Println()
	// Step 1: Create sample monitoring message
	fmt.Println("Step 1: Creating sample monitoring message...")
	sampleMessage := types.MonitoringMessage{
		MessageID:   "test-123",
		ClientID:    "test-client",
		Timestamp:   time.Now().Unix(),
		MessageType: types.MessageTypeQueryLogs,
		BatchSize:   1,
		Data: types.QueryLogEvent{
			Timestamp:    time.Now().Unix(),
			DatabaseName: "test_db",
			UserName:     "test_user",
			QueryHash:    "abc123",
			QueryPattern: "SELECT * FROM users WHERE id = ?",
			RawQuery:     "SELECT * FROM users WHERE id = 1",
			Duration:     150.5,
			QueryType:    "SELECT",
			TableAccess: []types.TableAccess{
				{
					Schema:     "public",
					Table:      "users",
					Columns:    []string{"id", "name", "email"},
					AccessType: "SELECT",
					IsLattIQ:   true,
					LattIQCols: []string{"name", "email"},
				},
			},
		},
		Version: version.Version(),
	}
	fmt.Printf("✓ Created monitoring message with ID: %s\n\n", sampleMessage.MessageID)

	// Step 2: Create batch payload
	fmt.Println("Step 2: Creating batch payload...")
	batchPayload := types.BatchPayload{
		ClientID:  "sen-sentinel-client-245db92b",
		Timestamp: time.Now().Unix(),
		BatchSize: 1,
		Messages:  []types.MonitoringMessage{sampleMessage},
		Metadata: map[string]interface{}{
			"transmission_time": time.Now().Unix(),
			"test":              true,
		},
	}

	// Serialize the payload
	payload, err := json.Marshal(batchPayload)
	if err != nil {
		log.Fatalf("Failed to marshal payload: %v", err)
	}
	fmt.Printf("✓ Created batch with %d messages (%d bytes)\n\n", batchPayload.BatchSize, len(payload))

	// Step 3: Generate HMAC signature
	fmt.Println("Step 3: Generating HMAC-SHA256 signature...")
	secretKey := "81ad4c2263c2787fa609b47a5203693f6db1edb95c1ba26804018428e19a1209"
	algorithm := "sha256"
	timestamp := time.Now().Unix()
	signature, err := hmac.GenerateClientSignature(secretKey, algorithm, "POST", "/watchtower/v1/events/batch", payload, timestamp)
	if err != nil {
		log.Fatalf("Failed to generate HMAC signature: %v", err)
	}
	fmt.Printf("✓ Generated HMAC signature: %s\n\n", signature)

	// Step 4: Send to LattIQ Watchtower using resty
	fmt.Println("Step 4: Sending to LattIQ Watchtower...")
	endpoint := "http://localhost:8081"
	fmt.Printf("Endpoint: %s\n", endpoint)
	fmt.Printf("Payload size: %d bytes\n", len(payload))
	fmt.Printf("Client ID: test-client\n")

	// Create resty client
	client := resty.New()

	// Send the request
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("User-Agent", "lattiq-sentinel/1.0").
		SetHeader("X-HMAC-Signature", signature).
		SetHeader("X-Timestamp", fmt.Sprintf("%d", timestamp)).
		SetHeader("X-Client-ID", "test-client").
		SetBody(payload).
		Post(endpoint)

	fmt.Println()
	if err != nil {
		fmt.Printf("✗ Request failed: %v\n", err)
		log.Fatalf("Failed to send request: %v", err)
	}

	fmt.Printf("✓ Response Status: %s\n", resp.Status())
	fmt.Printf("Response Body: %s\n", string(resp.Body()))

	fmt.Println()
	fmt.Println("Example completed!")

	if resp.IsSuccess() {
		fmt.Println("✓ Message successfully transmitted to LattIQ Watchtower")
	} else {
		fmt.Println("⚠ Non-success status code - check server logs or endpoint")
	}
}
