package scanner

import (
	"strings"
	"testing"
)

func TestGetRandomUserAgent(t *testing.T) {
	ua := GetRandomUserAgent()
	if ua == "" {
		t.Error("GetRandomUserAgent returned empty string")
	}
	if !strings.Contains(ua, "Mozilla") {
		t.Errorf("GetRandomUserAgent returned invalid UA: %s", ua)
	}
}

func TestGetUserAgentByBrowser(t *testing.T) {
	tests := []struct {
		browser string
		valid   bool
	}{
		{"chrome", true},
		{"firefox", true},
		{"safari", true},
		{"edge", true},
		{"opera", true},
		{"brave", true},
		{"mobile", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		ua := GetUserAgentByBrowser(tt.browser)
		if tt.valid && ua == "" {
			t.Errorf("GetUserAgentByBrowser(%q) returned empty string", tt.browser)
		}
		if !tt.valid && ua != "" {
			t.Errorf("GetUserAgentByBrowser(%q) should return empty string, got: %s", tt.browser, ua)
		}
		if tt.valid && !strings.Contains(ua, "Mozilla") {
			t.Errorf("GetUserAgentByBrowser(%q) returned invalid UA: %s", tt.browser, ua)
		}
	}
}

func TestGetUserAgentByName(t *testing.T) {
	tests := []struct {
		name     string
		contains string
		valid    bool
	}{
		{"chrome-windows", "Windows", true},
		{"chrome-mac", "Macintosh", true},
		{"chrome-linux", "Linux", true},
		{"firefox-windows", "Windows", true},
		{"firefox-mac", "Macintosh", true},
		{"firefox-linux", "Linux", true},
		{"safari-mac", "Safari", true},
		{"safari-ios", "iPhone", true},
		{"edge-windows", "Edg", true},
		{"edge-mac", "Edg", true},
		{"opera-windows", "OPR", true},
		{"opera-mac", "OPR", true},
		{"brave-windows", "Chrome", true},
		{"brave-mac", "Chrome", true},
		{"chrome-android", "Android", true},
		{"invalid-name", "", false},
	}

	for _, tt := range tests {
		ua := GetUserAgentByName(tt.name)
		if tt.valid && ua == "" {
			t.Errorf("GetUserAgentByName(%q) returned empty string", tt.name)
		}
		if !tt.valid && ua != "" {
			t.Errorf("GetUserAgentByName(%q) should return empty string, got: %s", tt.name, ua)
		}
		if tt.valid && !strings.Contains(ua, tt.contains) {
			t.Errorf("GetUserAgentByName(%q) should contain %q, got: %s", tt.name, tt.contains, ua)
		}
	}
}

func TestAllUserAgentsAreValid(t *testing.T) {
	if len(AllUserAgents) == 0 {
		t.Error("AllUserAgents is empty")
	}

	for _, ua := range AllUserAgents {
		if ua.String == "" {
			t.Errorf("User agent %s has empty string", ua.Name)
		}
		if ua.Name == "" {
			t.Error("User agent has empty name")
		}
		if !strings.Contains(ua.String, "Mozilla") {
			t.Errorf("User agent %s has invalid string: %s", ua.Name, ua.String)
		}
	}
}

func TestUserAgentsByBrowserMapping(t *testing.T) {
	expectedBrowsers := []string{"chrome", "firefox", "safari", "edge", "opera", "brave", "mobile"}

	for _, browser := range expectedBrowsers {
		agents, ok := UserAgentsByBrowser[browser]
		if !ok {
			t.Errorf("Browser %q not found in UserAgentsByBrowser", browser)
			continue
		}
		if len(agents) == 0 {
			t.Errorf("Browser %q has no user agents", browser)
		}
	}
}
