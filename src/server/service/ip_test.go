package service

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/apimgr/ipgaze/src/iputil/geo"
	"github.com/apimgr/ipgaze/src/server/model"
)

// stubReader satisfies geo.Reader without any real MMDB files.
type stubReader struct {
	country geo.Country
	city    geo.City
	asn     geo.ASN
	empty   bool
}

func (s *stubReader) Country(_ net.IP) (geo.Country, error) { return s.country, nil }
func (s *stubReader) City(_ net.IP) (geo.City, error)       { return s.city, nil }
func (s *stubReader) ASN(_ net.IP) (geo.ASN, error)         { return s.asn, nil }
func (s *stubReader) IsEmpty() bool                         { return s.empty }

// stubCache satisfies IPCache in memory.
type stubCache struct {
	entries map[string]model.IPLookupResponse
}

func newStubCache() *stubCache {
	return &stubCache{entries: make(map[string]model.IPLookupResponse)}
}

func (c *stubCache) Get(ip net.IP) (model.IPLookupResponse, bool) {
	r, ok := c.entries[ip.String()]
	return r, ok
}

func (c *stubCache) Set(ip net.IP, r model.IPLookupResponse) {
	c.entries[ip.String()] = r
}

func TestNewIPLookupService(t *testing.T) {
	svc := NewIPLookupService(&stubReader{}, newStubCache(), nil)
	if svc == nil {
		t.Fatal("NewIPLookupService returned nil")
	}
}

func TestLookup_CacheHit(t *testing.T) {
	cache := newStubCache()
	ip := net.ParseIP("1.2.3.4")
	expected := model.IPLookupResponse{IP: ip, Country: "Cached Country"}
	cache.Set(ip, expected)

	svc := NewIPLookupService(&stubReader{}, cache, nil)
	resp, err := svc.Lookup(ip)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if resp.Country != "Cached Country" {
		t.Errorf("Country = %q, want %q", resp.Country, "Cached Country")
	}
}

func TestLookup_CacheMiss_IPv4(t *testing.T) {
	eu := true
	reader := &stubReader{
		country: geo.Country{Name: "France", ISO: "FR", IsEU: &eu},
		city: geo.City{
			Name:       "Paris",
			RegionName: "Île-de-France",
			RegionCode: "IDF",
			PostalCode: "75001",
			Timezone:   "Europe/Paris",
			Latitude:   48.8566,
			Longitude:  2.3522,
		},
		asn: geo.ASN{
			AutonomousSystemNumber:       12345,
			AutonomousSystemOrganization: "Orange SA",
		},
	}
	cache := newStubCache()
	ip := net.ParseIP("1.2.3.4")

	svc := NewIPLookupService(reader, cache, nil)
	resp, err := svc.Lookup(ip)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if resp.IP.String() != ip.String() {
		t.Errorf("IP = %v, want %v", resp.IP, ip)
	}
	if resp.Country != "France" {
		t.Errorf("Country = %q, want %q", resp.Country, "France")
	}
	if resp.CountryISO != "FR" {
		t.Errorf("CountryISO = %q, want %q", resp.CountryISO, "FR")
	}
	if resp.CountryEU == nil || !*resp.CountryEU {
		t.Errorf("CountryEU = %v, want true", resp.CountryEU)
	}
	if resp.City != "Paris" {
		t.Errorf("City = %q, want %q", resp.City, "Paris")
	}
	if resp.RegionName != "Île-de-France" {
		t.Errorf("RegionName = %q, want %q", resp.RegionName, "Île-de-France")
	}
	if resp.PostalCode != "75001" {
		t.Errorf("PostalCode = %q, want %q", resp.PostalCode, "75001")
	}
	if resp.Timezone != "Europe/Paris" {
		t.Errorf("Timezone = %q, want %q", resp.Timezone, "Europe/Paris")
	}
	if resp.ASN != "AS12345" {
		t.Errorf("ASN = %q, want %q", resp.ASN, "AS12345")
	}
	if resp.ASNOrg != "Orange SA" {
		t.Errorf("ASNOrg = %q, want %q", resp.ASNOrg, "Orange SA")
	}
	if resp.IPDecimal == nil {
		t.Error("IPDecimal is nil")
	}
}

func TestLookup_ASNZero(t *testing.T) {
	reader := &stubReader{
		asn: geo.ASN{AutonomousSystemNumber: 0},
	}
	cache := newStubCache()
	ip := net.ParseIP("1.2.3.4")

	svc := NewIPLookupService(reader, cache, nil)
	resp, err := svc.Lookup(ip)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if resp.ASN != "" {
		t.Errorf("ASN = %q, want empty string when ASN number is 0", resp.ASN)
	}
}

func TestLookup_WithHostnameResolver(t *testing.T) {
	cache := newStubCache()
	ip := net.ParseIP("1.2.3.4")

	svc := NewIPLookupService(&stubReader{}, cache, func(resolveIP net.IP) (string, error) {
		return "host.example.com", nil
	})
	resp, err := svc.Lookup(ip)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if resp.Hostname != "host.example.com" {
		t.Errorf("Hostname = %q, want %q", resp.Hostname, "host.example.com")
	}
}

func TestLookup_HostnameResolverError(t *testing.T) {
	cache := newStubCache()
	ip := net.ParseIP("1.2.3.4")

	svc := NewIPLookupService(&stubReader{}, cache, func(resolveIP net.IP) (string, error) {
		return "", errors.New("no PTR record")
	})
	resp, err := svc.Lookup(ip)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if resp.Hostname != "" {
		t.Errorf("Hostname = %q, want empty on resolver error", resp.Hostname)
	}
}

func TestLookup_NilLookupAddr(t *testing.T) {
	cache := newStubCache()
	ip := net.ParseIP("1.2.3.4")

	svc := NewIPLookupService(&stubReader{}, cache, nil)
	resp, err := svc.Lookup(ip)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if resp.Hostname != "" {
		t.Errorf("Hostname = %q, want empty when lookupAddr is nil", resp.Hostname)
	}
}

func TestLookup_ResultCached(t *testing.T) {
	callCount := 0
	reader := &stubReader{
		country: geo.Country{Name: "Germany", ISO: "DE"},
	}
	cache := newStubCache()
	ip := net.ParseIP("5.6.7.8")

	svc := NewIPLookupService(reader, cache, func(_ net.IP) (string, error) {
		callCount++
		return "host.de", nil
	})

	_, err := svc.Lookup(ip)
	if err != nil {
		t.Fatalf("first Lookup error: %v", err)
	}
	_, err = svc.Lookup(ip)
	if err != nil {
		t.Fatalf("second Lookup error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("lookupAddr called %d times, want 1 (second call should hit cache)", callCount)
	}
}

func TestLookup_IPv6(t *testing.T) {
	cache := newStubCache()
	ip := net.ParseIP("2001:db8::1")

	svc := NewIPLookupService(&stubReader{}, cache, nil)
	resp, err := svc.Lookup(ip)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if resp.IPDecimal == nil {
		t.Error("IPDecimal is nil for IPv6")
	}
	if resp.IPDecimal.Sign() <= 0 {
		t.Errorf("IPDecimal = %v, want positive for 2001:db8::1", resp.IPDecimal)
	}
}

func TestLookup_MultipleIPs(t *testing.T) {
	cache := newStubCache()
	svc := NewIPLookupService(&stubReader{}, cache, nil)

	for i := 1; i <= 5; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.0.0.%d", i))
		resp, err := svc.Lookup(ip)
		if err != nil {
			t.Fatalf("Lookup(%v) error: %v", ip, err)
		}
		if resp.IPDecimal == nil {
			t.Errorf("IPDecimal is nil for %v", ip)
		}
	}
}
