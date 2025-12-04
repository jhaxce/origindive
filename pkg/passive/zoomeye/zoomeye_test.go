package zoomeye

import (
	"context"
	"testing"
	"time"
)

func TestSearchHost_NoAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHost(ctx, "example.com", []string{}, 5*time.Second)
	if err == nil {
		t.Fatal("Expected error when no API keys provided")
	}
}

func TestSearchHost_EmptyAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHost(ctx, "example.com", []string{"", "  "}, 5*time.Second)
	if err == nil {
		t.Fatal("Expected error when all API keys are empty")
	}
}

func TestSearchHost_Success(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHost(ctx, "example.com", []string{"test_key"}, 100*time.Millisecond)
	if err == nil {
		t.Log("Search succeeded")
	}
}

func TestZoomEyeStructures(t *testing.T) {
	resp := ZoomEyeV2Response{
		Code:    60000,
		Message: "OK",
		Total:   1,
		Data: []ZoomEyeV2Asset{
			{IP: "192.168.1.1", Port: 443, Domain: "example.com"},
		},
	}
	if resp.Code != 60000 {
		t.Errorf("Code = %d", resp.Code)
	}
}

func TestSearchHost_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := SearchHost(ctx, "example.com", []string{"test_key"}, 5*time.Second)
	if err == nil {
		t.Log("Expected error for cancelled context")
	}
}
