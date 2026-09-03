package service

import (
	"fmt"
	"net"

	"github.com/apimgr/ipgaze/src/iputil"
	"github.com/apimgr/ipgaze/src/iputil/geo"
	"github.com/apimgr/ipgaze/src/server/model"
)

// IPCache is the cache interface satisfied by server.Cache.
type IPCache interface {
	Get(net.IP) (model.IPLookupResponse, bool)
	Set(net.IP, model.IPLookupResponse)
}

// ThreatLookup is the interface for VPN/proxy/Tor detection.
// Satisfied by *threat.Lookup; nil disables threat detection silently.
type ThreatLookup interface {
	IsTor(net.IP) bool
	IsVPN(net.IP) bool
	IsProxy(net.IP) bool
}

// IPLookupService coordinates GeoIP lookups, caching, hostname resolution,
// and threat detection to produce a complete model.IPLookupResponse.
type IPLookupService struct {
	reader     geo.Reader
	cache      IPCache
	lookupAddr func(net.IP) (string, error)
	threat     ThreatLookup
}

// NewIPLookupService constructs an IPLookupService.
// Pass nil for lookupAddr to disable reverse hostname resolution.
// Pass nil for threat to disable VPN/proxy/Tor detection.
func NewIPLookupService(reader geo.Reader, cache IPCache, lookupAddr func(net.IP) (string, error)) *IPLookupService {
	return &IPLookupService{
		reader:     reader,
		cache:      cache,
		lookupAddr: lookupAddr,
	}
}

// SetThreatLookup attaches the threat detection lookup.
// Safe to call after construction; nil disables detection.
func (s *IPLookupService) SetThreatLookup(t ThreatLookup) {
	s.threat = t
}

// Lookup returns information about the given IP address.
// Results are cached; subsequent lookups for the same IP return the cached entry.
func (s *IPLookupService) Lookup(ip net.IP) (model.IPLookupResponse, error) {
	if resp, ok := s.cache.Get(ip); ok {
		return resp, nil
	}

	ipDecimal := iputil.ToDecimal(ip)
	country, _ := s.reader.Country(ip)
	city, _ := s.reader.City(ip)
	asn, _ := s.reader.ASN(ip)

	var hostname string
	if s.lookupAddr != nil {
		hostname, _ = s.lookupAddr(ip)
	}

	var asnNumber string
	if asn.AutonomousSystemNumber > 0 {
		asnNumber = fmt.Sprintf("AS%d", asn.AutonomousSystemNumber)
	}

	resp := model.IPLookupResponse{
		IP:         ip,
		IPDecimal:  ipDecimal,
		Country:    country.Name,
		CountryISO: country.ISO,
		CountryEU:  country.IsEU,
		RegionName: city.RegionName,
		RegionCode: city.RegionCode,
		MetroCode:  city.MetroCode,
		PostalCode: city.PostalCode,
		City:       city.Name,
		Latitude:   city.Latitude,
		Longitude:  city.Longitude,
		Timezone:   city.Timezone,
		ASN:        asnNumber,
		ASNOrg:     asn.AutonomousSystemOrganization,
		Hostname:   hostname,
	}

	// Threat detection: VPN, proxy, Tor exit-node classification.
	// Only populated when a ThreatLookup has been attached; nil = omitted from response.
	if s.threat != nil {
		isTor := s.threat.IsTor(ip)
		isVPN := s.threat.IsVPN(ip)
		isProxy := s.threat.IsProxy(ip)
		resp.IsTor = &isTor
		resp.IsVPN = &isVPN
		resp.IsProxy = &isProxy
	}

	s.cache.Set(ip, resp)
	return resp, nil
}
