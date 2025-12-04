package ip

import (
	"net"
	"testing"
)

func TestNewIterator(t *testing.T) {
	tests := []struct {
		name      string
		ranges    []IPRange
		wantTotal uint64
	}{
		{
			name:      "empty ranges",
			ranges:    []IPRange{},
			wantTotal: 0,
		},
		{
			name: "single IP",
			ranges: []IPRange{
				{Start: 0xC0A80101, End: 0xC0A80101}, // 192.168.1.1
			},
			wantTotal: 1,
		},
		{
			name: "single range",
			ranges: []IPRange{
				{Start: 0xC0A80101, End: 0xC0A80105}, // 192.168.1.1-192.168.1.5 (5 IPs)
			},
			wantTotal: 5,
		},
		{
			name: "multiple ranges",
			ranges: []IPRange{
				{Start: 0xC0A80101, End: 0xC0A80103}, // 192.168.1.1-192.168.1.3 (3 IPs)
				{Start: 0x0A000001, End: 0x0A000005}, // 10.0.0.1-10.0.0.5 (5 IPs)
			},
			wantTotal: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iter := NewIterator(tt.ranges)

			if iter.TotalIPs() != tt.wantTotal {
				t.Errorf("TotalIPs() = %d, want %d", iter.TotalIPs(), tt.wantTotal)
			}
		})
	}
}

func TestIterator_Next(t *testing.T) {
	ranges := []IPRange{
		{Start: 0xC0A80101, End: 0xC0A80103}, // 192.168.1.1-192.168.1.3 (3 IPs)
	}
	iter := NewIterator(ranges)

	expected := []string{
		"192.168.1.1",
		"192.168.1.2",
		"192.168.1.3",
	}

	for i, want := range expected {
		ip := iter.Next()
		if ip == nil {
			t.Fatalf("Next() returned nil at iteration %d, want %s", i, want)
		}
		got := ip.String()
		if got != want {
			t.Errorf("Next() iteration %d = %s, want %s", i, got, want)
		}
	}

	// Should return nil after exhausting
	ip := iter.Next()
	if ip != nil {
		t.Errorf("Next() after exhaustion = %v, want nil", ip)
	}
}

func TestIterator_NextUint32(t *testing.T) {
	ranges := []IPRange{
		{Start: 0xC0A80101, End: 0xC0A80102}, // 2 IPs
	}
	iter := NewIterator(ranges)

	// First IP
	ip1, ok1 := iter.NextUint32()
	if !ok1 {
		t.Error("NextUint32() first call should return ok=true")
	}
	if ip1 != 0xC0A80101 {
		t.Errorf("NextUint32() first IP = 0x%X, want 0xC0A80101", ip1)
	}

	// Second IP
	ip2, ok2 := iter.NextUint32()
	if !ok2 {
		t.Error("NextUint32() second call should return ok=true")
	}
	if ip2 != 0xC0A80102 {
		t.Errorf("NextUint32() second IP = 0x%X, want 0xC0A80102", ip2)
	}

	// Exhausted
	_, ok3 := iter.NextUint32()
	if ok3 {
		t.Error("NextUint32() after exhaustion should return ok=false")
	}
}

func TestIterator_MultipleRanges(t *testing.T) {
	ranges := []IPRange{
		{Start: 0xC0A80101, End: 0xC0A80102}, // 192.168.1.1-192.168.1.2 (2 IPs)
		{Start: 0x0A000001, End: 0x0A000002}, // 10.0.0.1-10.0.0.2 (2 IPs)
	}
	iter := NewIterator(ranges)

	expected := []uint32{
		0xC0A80101, // 192.168.1.1
		0xC0A80102, // 192.168.1.2
		0x0A000001, // 10.0.0.1
		0x0A000002, // 10.0.0.2
	}

	for i, want := range expected {
		ip, ok := iter.NextUint32()
		if !ok {
			t.Fatalf("NextUint32() returned ok=false at iteration %d, want IP", i)
		}
		if ip != want {
			t.Errorf("NextUint32() iteration %d = 0x%X, want 0x%X", i, ip, want)
		}
	}

	// Should be exhausted
	_, ok := iter.NextUint32()
	if ok {
		t.Error("NextUint32() after all ranges should return ok=false")
	}
}

func TestIterator_HasNext(t *testing.T) {
	ranges := []IPRange{
		{Start: 0xC0A80101, End: 0xC0A80101}, // 1 IP
	}
	iter := NewIterator(ranges)

	if !iter.HasNext() {
		t.Error("HasNext() should be true initially")
	}

	iter.Next()

	if iter.HasNext() {
		t.Error("HasNext() should be false after exhaustion")
	}
}

func TestIterator_Reset(t *testing.T) {
	ranges := []IPRange{
		{Start: 0xC0A80101, End: 0xC0A80102}, // 2 IPs
	}
	iter := NewIterator(ranges)

	// Consume all IPs
	iter.Next()
	iter.Next()

	if iter.HasNext() {
		t.Error("HasNext() should be false after consuming all IPs")
	}

	// Reset
	iter.Reset()

	if !iter.HasNext() {
		t.Error("HasNext() should be true after Reset()")
	}

	// Should get first IP again
	ip := iter.Next()
	if ip == nil {
		t.Fatal("Next() after Reset() should return first IP")
	}
	if ip.String() != "192.168.1.1" {
		t.Errorf("Next() after Reset() = %s, want 192.168.1.1", ip.String())
	}
}

func TestIterator_Channel(t *testing.T) {
	ranges := []IPRange{
		{Start: 0xC0A80101, End: 0xC0A80103}, // 192.168.1.1-192.168.1.3 (3 IPs)
	}
	iter := NewIterator(ranges)

	ch := iter.Channel(10)

	expected := []uint32{0xC0A80101, 0xC0A80102, 0xC0A80103}
	received := []uint32{}

	for ip := range ch {
		received = append(received, ip)
	}

	if len(received) != len(expected) {
		t.Fatalf("Channel() received %d IPs, want %d", len(received), len(expected))
	}

	for i, want := range expected {
		if received[i] != want {
			t.Errorf("Channel() IP %d = 0x%X, want 0x%X", i, received[i], want)
		}
	}
}

func TestIterator_EmptyRanges(t *testing.T) {
	iter := NewIterator([]IPRange{})

	if iter.TotalIPs() != 0 {
		t.Errorf("TotalIPs() for empty ranges = %d, want 0", iter.TotalIPs())
	}

	if iter.HasNext() {
		t.Error("HasNext() for empty ranges should be false")
	}

	ip := iter.Next()
	if ip != nil {
		t.Errorf("Next() for empty ranges = %v, want nil", ip)
	}

	ipUint, ok := iter.NextUint32()
	if ok {
		t.Errorf("NextUint32() for empty ranges should return ok=false, got ip=0x%X", ipUint)
	}
}

func TestIterator_LargeRange(t *testing.T) {
	// Test with a /24 network (254 IPs)
	ranges := []IPRange{
		{Start: 0xC0A80101, End: 0xC0A801FE}, // 192.168.1.1-192.168.1.254
	}
	iter := NewIterator(ranges)

	if iter.TotalIPs() != 254 {
		t.Errorf("TotalIPs() for /24 = %d, want 254", iter.TotalIPs())
	}

	count := 0
	for iter.HasNext() {
		iter.Next()
		count++
	}

	if count != 254 {
		t.Errorf("Iterated %d IPs, want 254", count)
	}
}

func TestIterator_ChannelBufferSize(t *testing.T) {
	ranges := []IPRange{
		{Start: 0xC0A80101, End: 0xC0A80164}, // 100 IPs
	}
	iter := NewIterator(ranges)

	// Test with small buffer
	ch := iter.Channel(5)

	count := 0
	for range ch {
		count++
	}

	if count != 100 {
		t.Errorf("Channel() received %d IPs, want 100", count)
	}
}

func TestIterator_FromUint32Conversion(t *testing.T) {
	ranges := []IPRange{
		{Start: 0x08080808, End: 0x08080808}, // 8.8.8.8
	}
	iter := NewIterator(ranges)

	ip := iter.Next()
	if ip == nil {
		t.Fatal("Next() returned nil")
	}

	expected := net.IPv4(8, 8, 8, 8)
	if !ip.Equal(expected) {
		t.Errorf("Next() = %s, want %s", ip.String(), expected.String())
	}
}

func TestIterator_SingleIPRange(t *testing.T) {
	// Single IP (start == end)
	ranges := []IPRange{
		{Start: 0xC0A80101, End: 0xC0A80101},
	}
	iter := NewIterator(ranges)

	if iter.TotalIPs() != 1 {
		t.Errorf("TotalIPs() for single IP = %d, want 1", iter.TotalIPs())
	}

	ip := iter.Next()
	if ip == nil {
		t.Fatal("Next() for single IP returned nil")
	}

	if ip.String() != "192.168.1.1" {
		t.Errorf("Next() = %s, want 192.168.1.1", ip.String())
	}

	// Should be exhausted
	ip2 := iter.Next()
	if ip2 != nil {
		t.Errorf("Next() after single IP = %v, want nil", ip2)
	}
}
