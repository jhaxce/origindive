package proxy

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestParseProxy(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"http://1.2.3.4:8080", false},
		{"socks5://1.2.3.4:1080", false},
		{"http://user:pass@1.2.3.4:8080", false},
		{"http://[invalid", true}, // Invalid URL syntax
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			p, err := ParseProxy(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Error("ParseProxy() expected error")
				}
				return
			}
			if err != nil {
				t.Errorf("ParseProxy() unexpected error: %v", err)
			}
			if p == nil {
				t.Error("ParseProxy() returned nil proxy")
			}
		})
	}
}

func TestProxy_GetHTTPClient(t *testing.T) {
	p, err := ParseProxy("http://1.2.3.4:8080")
	if err != nil {
		t.Fatalf("ParseProxy() error: %v", err)
	}

	client, err := p.GetHTTPClient(5 * time.Second)
	if err != nil {
		t.Fatalf("GetHTTPClient() error: %v", err)
	}

	if client == nil {
		t.Fatal("GetHTTPClient() returned nil")
	}

	if client.Timeout != 5*time.Second {
		t.Errorf("Client timeout = %v, want 5s", client.Timeout)
	}
}

func TestProxy_String(t *testing.T) {
	p, _ := ParseProxy("http://1.2.3.4:8080")
	if p.URL == "" {
		t.Error("URL is empty")
	}
}

func TestProxy_StringWithAuth(t *testing.T) {
	p, _ := ParseProxy("http://user:pass@1.2.3.4:8080")
	if p.URL == "" {
		t.Error("URL is empty")
	}
	if p.Username != "user" {
		t.Errorf("Username = %s, want user", p.Username)
	}
}

func TestFetchProxyList(t *testing.T) {
	t.Skip("Skipping network test")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proxies, err := FetchProxyList(ctx, nil, nil)
	if err != nil {
		t.Fatalf("FetchProxyList() error: %v", err)
	}

	// Should get some proxies (may be 0 if sources are down)
	if proxies == nil {
		t.Error("FetchProxyList() returned nil")
	}
}

func TestValidateProxies(t *testing.T) {
	t.Skip("Skipping network test")

	proxies := []*Proxy{
		{URL: "http://1.2.3.4:8080", Host: "1.2.3.4", Port: "8080"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	validated := ValidateProxies(ctx, proxies, 3*time.Second, 2)
	// May return 0 if proxy is invalid
	if validated == nil {
		t.Error("ValidateProxies() returned nil")
	}
}

func TestGetRandomProxy(t *testing.T) {
	proxies := []*Proxy{
		{URL: "http://1.1.1.1:8080", Host: "1.1.1.1", Port: "8080"},
		{URL: "http://2.2.2.2:8080", Host: "2.2.2.2", Port: "8080"},
	}

	p := GetRandomProxy(proxies)
	if p == nil {
		t.Error("GetRandomProxy() returned nil")
	}
}

func TestGetRandomProxy_Empty(t *testing.T) {
	p := GetRandomProxy([]*Proxy{})
	if p != nil {
		t.Error("GetRandomProxy([]) should return nil")
	}
}

func TestProxy_TestProxy(t *testing.T) {
	t.Skip("Skipping network test")

	p, _ := ParseProxy("http://invalid:9999")
	err := p.TestProxy(2 * time.Second)
	// Should fail for invalid proxy
	if err == nil {
		t.Error("TestProxy() with invalid proxy should fail")
	}
}

func TestParseProxy_SOCKS5(t *testing.T) {
	p, err := ParseProxy("socks5://1.2.3.4:1080")
	if err != nil {
		t.Fatalf("ParseProxy() SOCKS5 error: %v", err)
	}
	if p == nil {
		t.Fatal("ParseProxy() returned nil")
	}
}

func TestProxy_GetHTTPClient_SOCKS5(t *testing.T) {
	p, _ := ParseProxy("socks5://1.2.3.4:1080")
	client, err := p.GetHTTPClient(5 * time.Second)
	if err != nil {
		t.Fatalf("GetHTTPClient() SOCKS5 error: %v", err)
	}
	if client == nil {
		t.Fatal("GetHTTPClient() SOCKS5 returned nil")
	}
}

func TestParseProxy_WithCredentials(t *testing.T) {
	p, err := ParseProxy("http://user:pass@1.2.3.4:8080")
	if err != nil {
		t.Fatalf("ParseProxy() with auth error: %v", err)
	}
	if p == nil {
		t.Fatal("ParseProxy() returned nil")
	}
	// Just verify it parses successfully
}

func TestParseProxy_InvalidPort(t *testing.T) {
	_, err := ParseProxy("http://1.2.3.4:invalid")
	if err == nil {
		t.Error("ParseProxy() with invalid port should fail")
	}
}

func TestParseProxy_MissingPort(t *testing.T) {
	p, err := ParseProxy("http://1.2.3.4")
	if err != nil {
		t.Errorf("ParseProxy() without port should succeed: %v", err)
	}
	if p.Port != "8080" {
		t.Errorf("ParseProxy() default port = %s, want 8080", p.Port)
	}
}

func TestPublicProxySources(t *testing.T) {
	sources := GetPublicProxySources()
	if len(sources) == 0 {
		t.Error("GetPublicProxySources() should not return empty slice")
	}

	// Check URLs are valid
	for _, url := range sources {
		if url == "" {
			t.Error("GetPublicProxySources() contains empty URL")
		}
	}
}

func TestProxy_HTTPClient_Timeout(t *testing.T) {
	p, _ := ParseProxy("http://1.2.3.4:8080")
	client, _ := p.GetHTTPClient(10 * time.Second)

	if client.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", client.Timeout)
	}
}

func TestProxy_Type(t *testing.T) {
	tests := []struct {
		url string
	}{
		{"http://1.2.3.4:8080"},
		{"https://1.2.3.4:8080"},
		{"socks5://1.2.3.4:1080"},
	}

	for _, tt := range tests {
		p, err := ParseProxy(tt.url)
		if err != nil {
			t.Fatalf("ParseProxy(%s) error: %v", tt.url, err)
		}
		if p == nil {
			t.Fatalf("ParseProxy(%s) returned nil", tt.url)
		}
	}
}

func TestProxy_HTTPTransport(t *testing.T) {
	p, _ := ParseProxy("http://1.2.3.4:8080")
	client, _ := p.GetHTTPClient(5 * time.Second)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Error("Client transport is not *http.Transport")
	}

	if transport.Proxy == nil {
		t.Error("Transport.Proxy is nil")
	}
}
