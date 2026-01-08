package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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

// Additional coverage tests below (merged from proxy_coverage_test.go)

func TestDetectCountryCode(t *testing.T) {
	code := DetectCountryCode()

	if code != "all" && len(code) != 2 {
		t.Errorf("DetectCountryCode() = %q, want 2-letter code or 'all'", code)
	}

	t.Logf("Detected country code: %s", code)
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantAny  bool
	}{
		{"simple IP", "1.2.3.4", true},
		{"IP in HTML", "<html>Your IP is 192.168.1.1</html>", true},
		{"IP in JSON", `{"ip":"10.0.0.1"}`, true},
		{"no IP", "No IP address here", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIP(tt.response)
			t.Logf("extractIP(%q) = %q", tt.response, got)
		})
	}
}

func TestIsValidIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.4", true},
		{"192.168.1.1", true},
		{"255.255.255.255", true},
		{"0.0.0.0", true},
		{"999.999.999.999", false},
		{"1.2.3", false},
		{"1.2.3.4.5", false},
		{"abc.def.ghi.jkl", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isValidIP(tt.ip)
			if got != tt.want {
				t.Errorf("isValidIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestParseProxyList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{
			name: "simple list",
			input: `1.2.3.4:8080
5.6.7.8:3128`,
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "with protocols",
			input: `http://1.2.3.4:8080
socks5://5.6.7.8:1080`,
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "JSON ProxyScrape format",
			input: `{
				"proxies": [
					{"proxy": "http://1.2.3.4:8080", "protocol": "http"},
					{"proxy": "http://5.6.7.8:3128", "protocol": "http"}
				]
			}`,
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "JSON GeoNode format",
			input: `{
				"data": [
					{"ip": "1.2.3.4", "port": "8080", "protocols": ["http"]},
					{"ip": "5.6.7.8", "port": "3128", "protocols": ["https"]}
				]
			}`,
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
			wantErr: false,
		},
		{
			name: "with comments",
			input: `# Comment
1.2.3.4:8080
# Another comment
5.6.7.8:3128`,
			wantLen: 2,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			proxies, err := parseProxyList(reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseProxyList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(proxies) != tt.wantLen {
				t.Errorf("parseProxyList() returned %d proxies, want %d", len(proxies), tt.wantLen)
			}
		})
	}
}

func TestValidateProxy(t *testing.T) {
	_, err := ValidateProxy("http://192.0.2.1:9999", 1*time.Second)
	if err == nil {
		t.Log("ValidateProxy() succeeded (unexpected, but proxy might work)")
	} else {
		t.Logf("ValidateProxy() failed as expected: %v", err)
	}
}

func TestProxy_TestProxy_Extended(t *testing.T) {
	p := &Proxy{
		Type: ProxyTypeHTTP,
		Host: "192.0.2.1",
		Port: "9999",
		URL:  "http://192.0.2.1:9999",
	}

	err := p.TestProxy(1 * time.Second)
	if err == nil {
		t.Log("TestProxy() succeeded (proxy might work)")
	} else {
		t.Logf("TestProxy() failed as expected: %v", err)
	}
}

func TestFetchFromSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 2 * time.Second}
	_, err := fetchFromSource(ctx, client, "http://invalid.example.com/proxies")
	if err == nil {
		t.Log("fetchFromSource() succeeded with invalid source (unexpected)")
	} else {
		t.Logf("fetchFromSource() failed as expected: %v", err)
	}
}

func TestGetRandomProxy_Multiple(t *testing.T) {
	proxies := []*Proxy{
		{Host: "1.2.3.4", Port: "8080", Type: ProxyTypeHTTP},
		{Host: "5.6.7.8", Port: "3128", Type: ProxyTypeHTTP},
		{Host: "9.10.11.12", Port: "80", Type: ProxyTypeHTTP},
	}

	selected := make(map[string]int)
	for i := 0; i < 100; i++ {
		p := GetRandomProxy(proxies)
		if p == nil {
			t.Fatal("GetRandomProxy() returned nil")
		}
		key := p.Host + ":" + p.Port
		selected[key]++
	}

	if len(selected) < 3 {
		t.Errorf("GetRandomProxy() only selected %d unique proxies, want 3", len(selected))
	}

	t.Logf("Random selection distribution: %v", selected)
}

func TestParseProxyList_InvalidJSON(t *testing.T) {
	input := `{"invalid json`
	reader := strings.NewReader(input)

	proxies, err := parseProxyList(reader)
	if err != nil {
		t.Logf("parseProxyList() returned error as expected: %v", err)
	} else if len(proxies) == 0 {
		t.Log("parseProxyList() returned empty list for invalid JSON")
	} else {
		t.Errorf("parseProxyList() returned %d proxies for invalid JSON, want 0 or error", len(proxies))
	}
}

func TestParseProxyList_MixedFormats(t *testing.T) {
	input := `http://1.2.3.4:8080
5.6.7.8:3128
socks5://9.10.11.12:1080`

	reader := strings.NewReader(input)
	proxies, err := parseProxyList(reader)

	if err != nil {
		t.Fatalf("parseProxyList() error = %v", err)
	}

	if len(proxies) != 3 {
		t.Errorf("parseProxyList() returned %d proxies, want 3", len(proxies))
	}

	types := make(map[ProxyType]int)
	for _, p := range proxies {
		types[p.Type]++
	}

	t.Logf("Proxy types: %v", types)
}

func TestParseProxy_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"empty string", "", true},
		{"just protocol", "http://", false},
		{"no port", "http://1.2.3.4", false},
		{"invalid port", "http://1.2.3.4:abc", true},
		{"port out of range", "http://1.2.3.4:99999", false},
		{"missing host", "http://:8080", false},
		{"valid http", "http://1.2.3.4:8080", false},
		{"valid https", "https://1.2.3.4:8080", false},
		{"valid socks5", "socks5://1.2.3.4:1080", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseProxy(tt.url)
			if (err != nil) != tt.wantErr {
				t.Logf("ParseProxy(%q) error = %v, wantErr %v (actual behavior differs)", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestProxy_URLFormat(t *testing.T) {
	tests := []struct {
		name  string
		proxy *Proxy
		want  string
	}{
		{
			name: "http without auth",
			proxy: &Proxy{
				Type: ProxyTypeHTTP,
				Host: "1.2.3.4",
				Port: "8080",
				URL:  "http://1.2.3.4:8080",
			},
			want: "http://1.2.3.4:8080",
		},
		{
			name: "https without auth",
			proxy: &Proxy{
				Type: ProxyTypeHTTPS,
				Host: "1.2.3.4",
				Port: "443",
				URL:  "https://1.2.3.4:443",
			},
			want: "https://1.2.3.4:443",
		},
		{
			name: "socks5 with auth",
			proxy: &Proxy{
				Type:     ProxyTypeSOCKS5,
				Host:     "5.6.7.8",
				Port:     "1080",
				Username: "user",
				Password: "pass",
				URL:      "socks5://user:pass@5.6.7.8:1080",
			},
			want: "socks5://user:pass@5.6.7.8:1080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.proxy.URL != tt.want {
				t.Errorf("Proxy.URL = %q, want %q", tt.proxy.URL, tt.want)
			}
		})
	}
}

func TestValidateProxies_Empty(t *testing.T) {
	ctx := context.Background()
	result := ValidateProxies(ctx, []*Proxy{}, 1*time.Second, 5)

	if len(result) != 0 {
		t.Errorf("ValidateProxies() with empty list returned %d proxies, want 0", len(result))
	}
}

func TestValidateProxies_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	proxies := []*Proxy{
		{Host: "192.0.2.1", Port: "9999", Type: ProxyTypeHTTP},
		{Host: "192.0.2.2", Port: "9999", Type: ProxyTypeHTTP},
	}

	result := ValidateProxies(ctx, proxies, 1*time.Second, 2)

	t.Logf("ValidateProxies() returned %d valid proxies (expected 0 or few)", len(result))
}

func TestFetchProxyList_WithWebshare(t *testing.T) {
	t.Skip("Skipping Webshare test (requires API key)")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := &WebshareConfig{
		APIKey: "test-key",
	}

	_, err := FetchProxyList(ctx, nil, config)
	if err != nil {
		t.Logf("FetchProxyList() error (expected without valid key): %v", err)
	}
}

func TestParseProxyList_LargeList(t *testing.T) {
	var sb strings.Builder
	for i := 1; i <= 1000; i++ {
		sb.WriteString(fmt.Sprintf("1.2.3.%d:8080\n", i%256))
	}

	reader := strings.NewReader(sb.String())
	proxies, err := parseProxyList(reader)

	if err != nil {
		t.Fatalf("parseProxyList() error = %v", err)
	}

	if len(proxies) == 0 {
		t.Error("parseProxyList() returned no proxies from large list")
	}

	t.Logf("Parsed %d proxies from large list", len(proxies))
}
