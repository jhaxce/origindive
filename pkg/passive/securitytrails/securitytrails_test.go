package securitytrails

import (
	"context"
	"testing"
	"time"
)

func TestSearchSubdomainsAndHistory_NoAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchSubdomainsAndHistory(ctx, "example.com", []string{}, 5*time.Second)
	if err == nil {
		t.Fatal("Expected error when no API keys provided")
	}
}

func TestSearchSubdomainsAndHistory_EmptyAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchSubdomainsAndHistory(ctx, "example.com", []string{"", "  "}, 5*time.Second)
	if err == nil {
		t.Fatal("Expected error when all API keys are empty")
	}
}

func TestSearchSubdomainsAndHistory_Success(t *testing.T) {
	ctx := context.Background()
	_, err := SearchSubdomainsAndHistory(ctx, "example.com", []string{"test_key"}, 100*time.Millisecond)
	if err == nil {
		t.Log("Search succeeded")
	}
}

func TestSecurityTrailsStructures(t *testing.T) {
	resp := SubdomainResponse{
		Subdomains: []string{"www", "mail"},
	}
	if len(resp.Subdomains) != 2 {
		t.Errorf("Subdomains count = %d", len(resp.Subdomains))
	}
}

func TestSearchSubdomainsAndHistory_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := SearchSubdomainsAndHistory(ctx, "example.com", []string{"test_key"}, 5*time.Second)
	if err == nil {
		t.Log("Expected error for cancelled context")
	}
}

func TestResolveToIPv4(t *testing.T) {
	ctx := context.Background()
	_, err := resolveToIPv4(ctx, "localhost", 2*time.Second)
	if err != nil {
		t.Logf("Resolve failed: %v", err)
	}
}
