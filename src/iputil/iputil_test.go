package iputil

import (
	"math/big"
	"net"
	"testing"
)

func TestToDecimal(t *testing.T) {
	var msb = new(big.Int)
	msb, _ = msb.SetString("80000000000000000000000000000000", 16)

	var tests = []struct {
		in  string
		out *big.Int
	}{
		{"127.0.0.1", big.NewInt(2130706433)},
		{"::1", big.NewInt(1)},
		{"8000::", msb},
	}
	for _, tt := range tests {
		i := ToDecimal(net.ParseIP(tt.in))
		if tt.out.Cmp(i) != 0 {
			t.Errorf("Expected %d, got %d for IP %s", tt.out, i, tt.in)
		}
	}
}

func TestToDecimal_IPv4Mapped(t *testing.T) {
	// IPv4-mapped IPv6 address (::ffff:192.0.2.1) should decode as IPv4
	ip := net.ParseIP("192.0.2.1")
	result := ToDecimal(ip)
	expected := big.NewInt(3221225985) // 192*16777216 + 0*65536 + 2*256 + 1
	if expected.Cmp(result) != 0 {
		t.Errorf("ToDecimal(192.0.2.1) = %d, want %d", result, expected)
	}
}

func TestToDecimal_AllZerosIPv4(t *testing.T) {
	ip := net.ParseIP("0.0.0.0")
	result := ToDecimal(ip)
	if result.Sign() != 0 {
		t.Errorf("ToDecimal(0.0.0.0) = %d, want 0", result)
	}
}

func TestToDecimal_AllZerosIPv6(t *testing.T) {
	ip := net.ParseIP("::")
	result := ToDecimal(ip)
	if result.Sign() != 0 {
		t.Errorf("ToDecimal(::) = %d, want 0", result)
	}
}

func TestToDecimal_MaxIPv4(t *testing.T) {
	ip := net.ParseIP("255.255.255.255")
	result := ToDecimal(ip)
	expected := big.NewInt(4294967295)
	if expected.Cmp(result) != 0 {
		t.Errorf("ToDecimal(255.255.255.255) = %d, want %d", result, expected)
	}
}

func TestLookupAddr_InvalidIP(t *testing.T) {
	// Loopback reverse lookup — may succeed or fail depending on /etc/hosts; just must not panic
	ip := net.ParseIP("127.0.0.1")
	_, _ = LookupAddr(ip)
}

func TestLookupAddr_RFC1918(t *testing.T) {
	// Private address reverse lookup — expected to return empty or an error in CI
	ip := net.ParseIP("192.168.0.1")
	_, _ = LookupAddr(ip)
}

func TestLookupPort_ClosedPort(t *testing.T) {
	// Port 1 on loopback is almost certainly closed — expect an error
	ip := net.ParseIP("127.0.0.1")
	err := LookupPort(ip, 1)
	if err == nil {
		t.Log("LookupPort(127.0.0.1, 1) unexpectedly succeeded — port may be open in this environment")
	}
}

func TestLookupPort_InvalidPort(t *testing.T) {
	// Port 0 — should fail to connect
	ip := net.ParseIP("127.0.0.1")
	err := LookupPort(ip, 0)
	if err == nil {
		t.Log("LookupPort(127.0.0.1, 0) unexpectedly succeeded")
	}
}
