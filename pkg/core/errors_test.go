package core

import (
	"errors"
	"testing"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrNoDomain", ErrNoDomain, "domain is required"},
		{"ErrNoIPRange", ErrNoIPRange, "IP range is required for active scan"},
		{"ErrTooManyWorkers", ErrTooManyWorkers, "worker count exceeds maximum (1000)"},
		{"ErrInvalidCIDR", ErrInvalidCIDR, "invalid CIDR notation"},
		{"ErrInvalidIP", ErrInvalidIP, "invalid IP address"},
		{"ErrInvalidConfig", ErrInvalidConfig, "invalid configuration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
			if tt.err.Error() != tt.msg {
				t.Errorf("%s message = %q, want %q", tt.name, tt.err.Error(), tt.msg)
			}
			// Test that errors.Is works
			if !errors.Is(tt.err, tt.err) {
				t.Errorf("errors.Is(%s, %s) = false, want true", tt.name, tt.name)
			}
		})
	}
}
