package iputil

import (
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// LookupAddr resolves the reverse-DNS (PTR) hostname for ip and returns it
// unrooted (no trailing dot). An empty string is returned when the lookup
// fails or the address has no PTR record.
func LookupAddr(ip net.IP) (string, error) {
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return "", err
	}
	// Always return unrooted name
	return strings.TrimRight(names[0], "."), nil
}

// LookupPort reports whether a TCP connection to ip:port can be established
// within a two-second timeout. A nil error means the port is reachable.
func LookupPort(ip net.IP, port uint64) error {
	address := fmt.Sprintf("[%s]:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

// ToDecimal converts an IPv4 or IPv6 address to its unsigned integer form,
// the value reported as ip_decimal in API responses.
func ToDecimal(ip net.IP) *big.Int {
	i := big.NewInt(0)
	if to4 := ip.To4(); to4 != nil {
		i.SetBytes(to4)
	} else {
		i.SetBytes(ip)
	}
	return i
}
