// Package ip provides IP address parsing and validation utilities
package ip

import (
	"fmt"
	"net"
	"strings"

	"github.com/jhaxce/origindive/v3/pkg/core"
)

// ParseIP parses an IP address string
func ParseIP(ipStr string) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil, core.ErrInvalidIP
	}
	return ip, nil
}

// ParseCIDR parses a CIDR notation string
func ParseCIDR(cidr string) (net.IP, *net.IPNet, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, nil, core.ErrInvalidCIDR
	}
	return ip, network, nil
}

// ParseIPOrCIDR attempts to parse input as either an IP or CIDR
func ParseIPOrCIDR(input string) (ip net.IP, network *net.IPNet, isCIDR bool, err error) {
	input = strings.TrimSpace(input)

	// Try CIDR first
	if strings.Contains(input, "/") {
		ip, network, err = ParseCIDR(input)
		if err == nil {
			return ip, network, true, nil
		}
	}

	// Try as single IP
	ip, err = ParseIP(input)
	if err == nil {
		return ip, nil, false, nil
	}

	return nil, nil, false, fmt.Errorf("invalid IP or CIDR: %s", input)
}

// IsIPv4 checks if an IP is IPv4
func IsIPv4(ip net.IP) bool {
	return ip != nil && ip.To4() != nil
}

// IsIPv6 checks if an IP is IPv6
func IsIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}

// ToUint32 converts an IPv4 address to uint32 for range operations
func ToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not a valid IPv4 address")
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]), nil
}

// FromUint32 converts a uint32 back to an IPv4 address
func FromUint32(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// IPRange represents an IP range as uint32 values for efficient iteration
type IPRange struct {
	Start uint32
	End   uint32
}

// ParseIPRange parses start and end IP addresses into a range
func ParseIPRange(startIP, endIP string) (*IPRange, error) {
	start, err := ParseIP(startIP)
	if err != nil {
		return nil, fmt.Errorf("invalid start IP: %w", err)
	}

	end, err := ParseIP(endIP)
	if err != nil {
		return nil, fmt.Errorf("invalid end IP: %w", err)
	}

	startInt, err := ToUint32(start)
	if err != nil {
		return nil, fmt.Errorf("start IP must be IPv4: %w", err)
	}

	endInt, err := ToUint32(end)
	if err != nil {
		return nil, fmt.Errorf("end IP must be IPv4: %w", err)
	}

	if startInt > endInt {
		return nil, fmt.Errorf("start IP is greater than end IP")
	}

	return &IPRange{Start: startInt, End: endInt}, nil
}

// ParseCIDRRange parses a CIDR notation into an IP range
func ParseCIDRRange(cidr string) (*IPRange, error) {
	ip, network, err := ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Only support IPv4 for now
	if !IsIPv4(ip) {
		return nil, fmt.Errorf("only IPv4 CIDR is supported")
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("invalid network mask size")
	}

	// Calculate network address
	networkInt, _ := ToUint32(ip.Mask(network.Mask))

	var first, last uint32

	// For origin IP discovery, we want to scan ALL IPs in the range
	// including network and broadcast addresses, as they may respond
	// in cloud environments (AWS, Azure, etc.) or misconfigured networks
	if ones == 32 {
		// /32 single host
		first = networkInt
		last = networkInt
	} else if ones == 31 {
		// /31 point-to-point: both IPs usable (RFC 3021)
		first = networkInt
		last = networkInt + 1
	} else {
		// All other subnets: scan entire range including network and broadcast
		broadcast := networkInt | ^ToUint32FromMask(network.Mask)
		first = networkInt
		last = broadcast
	}

	return &IPRange{Start: first, End: last}, nil
}

// ToUint32FromMask converts a network mask to uint32
func ToUint32FromMask(mask net.IPMask) uint32 {
	if len(mask) != 4 {
		return 0
	}
	return uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
}

// Count returns the number of IPs in the range
func (r *IPRange) Count() uint64 {
	return uint64(r.End-r.Start) + 1
}

// Contains checks if an IP (as uint32) is within the range
func (r *IPRange) Contains(ip uint32) bool {
	return ip >= r.Start && ip <= r.End
}
