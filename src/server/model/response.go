// Package model contains data structures for the server
// Per AI.md: model/ for data models, structs, validation, serialization
package model

import (
	"math/big"
	"net"
	"time"

	"github.com/apimgr/ipgaze/src/useragent"
)

// IPLookupResponse represents the main IP lookup response
type IPLookupResponse struct {
	IP         net.IP               `json:"ip"`
	IPDecimal  *big.Int             `json:"ip_decimal"`
	Country    string               `json:"country,omitempty"`
	CountryISO string               `json:"country_iso,omitempty"`
	CountryEU  *bool                `json:"country_eu,omitempty"`
	RegionName string               `json:"region_name,omitempty"`
	RegionCode string               `json:"region_code,omitempty"`
	MetroCode  uint                 `json:"metro_code,omitempty"`
	PostalCode string               `json:"zip_code,omitempty"`
	City       string               `json:"city,omitempty"`
	Latitude   float64              `json:"latitude,omitempty"`
	Longitude  float64              `json:"longitude,omitempty"`
	Timezone   string               `json:"time_zone,omitempty"`
	ASN        string               `json:"asn,omitempty"`
	ASNOrg     string               `json:"asn_org,omitempty"`
	Hostname   string               `json:"hostname,omitempty"`
	UserAgent  *useragent.UserAgent `json:"user_agent,omitempty"`
	// IsVPN is true when the IP is associated with a known VPN or hosting provider.
	IsVPN *bool `json:"is_vpn,omitempty"`
	// IsProxy is true when the IP is a known open proxy or data-center proxy.
	IsProxy *bool `json:"is_proxy,omitempty"`
	// IsTor is true when the IP is a known Tor exit node.
	IsTor *bool `json:"is_tor,omitempty"`
	// IsTorHiddenService is true when this request arrived on the server's
	// own .onion address (AI.md PART 31/12). Tor hidden-service circuits never
	// carry the visitor's real IP to the server — IP above is only the local
	// loopback address Tor's ADD_ONION forwarding delivers, not the visitor's
	// address; consumers should treat IP as not meaningful when this is true.
	IsTorHiddenService *bool `json:"is_tor_hidden_service,omitempty"`
}

// PortResponse represents a port check response
type PortResponse struct {
	IP        net.IP `json:"ip"`
	Port      uint64 `json:"port"`
	Reachable bool   `json:"reachable"`
}

// HealthResponse - canonical field order for /server/healthz
type HealthResponse struct {
	Project        ProjectInfo  `json:"project"`
	Status         string       `json:"status"`
	PendingRestart bool         `json:"pending_restart,omitempty"`
	RestartReason  []string     `json:"restart_reason,omitempty"`
	Version        string       `json:"version"`
	GoVersion      string       `json:"go_version"`
	Build          BuildInfo    `json:"build"`
	Uptime         string       `json:"uptime"`
	Mode           string       `json:"mode"`
	Timestamp      time.Time    `json:"timestamp"`
	Features       FeaturesInfo `json:"features"`
	Checks         ChecksInfo   `json:"checks"`
	Stats          StatsInfo    `json:"stats"`
}

// ProjectInfo contains project branding fields
type ProjectInfo struct {
	Name        string `json:"name"`
	Tagline     string `json:"tagline"`
	Description string `json:"description"`
}

// BuildInfo contains VCS build metadata
type BuildInfo struct {
	Commit string `json:"commit"`
	Date   string `json:"date"`
}

// TorInfo contains Tor hidden-service status
type TorInfo struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	Hostname string `json:"hostname"`
}

// I2PInfo contains I2P eepsite status
type I2PInfo struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	Hostname string `json:"hostname"`
	// Provider names the eepsite backend: "i2pd", "sam", or "none".
	Provider string `json:"provider"`
}

// FeaturesInfo lists optional feature states
type FeaturesInfo struct {
	Tor   TorInfo `json:"tor"`
	I2P   I2PInfo `json:"i2p"`
	GeoIP bool    `json:"geoip"`
}

// ChecksInfo contains individual subsystem health results
type ChecksInfo struct {
	Database  string `json:"database"`
	Cache     string `json:"cache"`
	Disk      string `json:"disk"`
	Scheduler string `json:"scheduler"`
	Tor       string `json:"tor,omitempty"`
	I2P       string `json:"i2p,omitempty"`
}

// StatsInfo contains aggregate request counters
type StatsInfo struct {
	RequestsTotal int64 `json:"requests_total"`
	Requests24h   int64 `json:"requests_24h"`
	ActiveConns   int   `json:"active_connections"`
}
