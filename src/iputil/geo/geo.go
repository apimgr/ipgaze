package geo

import (
	"math"
	"net"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

type Reader interface {
	Country(net.IP) (Country, error)
	City(net.IP) (City, error)
	ASN(net.IP) (ASN, error)
	IsEmpty() bool
}

type Country struct {
	Name string
	ISO  string
	IsEU *bool
}

type City struct {
	Name       string
	Latitude   float64
	Longitude  float64
	PostalCode string
	Timezone   string
	MetroCode  uint
	RegionName string
	RegionCode string
}

type ASN struct {
	AutonomousSystemNumber       uint
	AutonomousSystemOrganization string
}

// sapics/ip-location-db MMDB struct definitions.
// Field tags match the actual MMDB field names from sapics/ip-location-db.
// Do NOT use geoip2-golang — it enforces MaxMind-branded database_type strings
// and rejects sapics files (type strings like "asn ipv4", "country ipvAll", etc.).

type asnRecord struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

type countryRecord struct {
	CountryCode string `maxminddb:"country_code"`
}

type cityRecord struct {
	City        string  `maxminddb:"city"`
	CountryCode string  `maxminddb:"country_code"`
	Latitude    float64 `maxminddb:"latitude"`
	Longitude   float64 `maxminddb:"longitude"`
	Postcode    string  `maxminddb:"postcode"`
	State1      string  `maxminddb:"state1"`
	State2      string  `maxminddb:"state2"`
	Timezone    string  `maxminddb:"timezone"`
}

type geoip struct {
	country *maxminddb.Reader
	cityV4  *maxminddb.Reader
	cityV6  *maxminddb.Reader
	asn     *maxminddb.Reader
}

// Open opens the GeoIP databases at the given paths.
// Empty string paths are skipped (no error). Any opened DB is valid for use.
// Per AI.md PART 19, city is two separate databases (IPv4 and IPv6) —
// City() picks cityV4DB or cityV6DB based on the looked-up IP's family.
func Open(countryDB, cityV4DB, cityV6DB, asnDB string) (Reader, error) {
	var country, cityV4, cityV6, asn *maxminddb.Reader
	if countryDB != "" {
		r, err := maxminddb.Open(countryDB)
		if err != nil {
			return nil, err
		}
		country = r
	}
	if cityV4DB != "" {
		r, err := maxminddb.Open(cityV4DB)
		if err != nil {
			return nil, err
		}
		cityV4 = r
	}
	if cityV6DB != "" {
		r, err := maxminddb.Open(cityV6DB)
		if err != nil {
			return nil, err
		}
		cityV6 = r
	}
	if asnDB != "" {
		r, err := maxminddb.Open(asnDB)
		if err != nil {
			return nil, err
		}
		asn = r
	}
	return &geoip{country: country, cityV4: cityV4, cityV6: cityV6, asn: asn}, nil
}

// euMembers is the set of ISO 3166-1 alpha-2 codes for EU member states.
// EU membership is stable; changes are rare and announced well in advance.
// Current members: 27 countries (as of 2024).
// Source: https://european-union.europa.eu/principles-countries-history/country-profiles_en
var euMembers = map[string]bool{
	// Austria
	"AT": true,
	// Belgium
	"BE": true,
	// Bulgaria
	"BG": true,
	// Cyprus
	"CY": true,
	// Czech Republic
	"CZ": true,
	// Germany
	"DE": true,
	// Denmark
	"DK": true,
	// Estonia
	"EE": true,
	// Spain
	"ES": true,
	// Finland
	"FI": true,
	// France
	"FR": true,
	// Greece
	"GR": true,
	// Croatia
	"HR": true,
	// Hungary
	"HU": true,
	// Ireland
	"IE": true,
	// Italy
	"IT": true,
	// Lithuania
	"LT": true,
	// Luxembourg
	"LU": true,
	// Latvia
	"LV": true,
	// Malta
	"MT": true,
	// Netherlands
	"NL": true,
	// Poland
	"PL": true,
	// Portugal
	"PT": true,
	// Romania
	"RO": true,
	// Sweden
	"SE": true,
	// Slovenia
	"SI": true,
	// Slovakia
	"SK": true,
}

// IsEUMember reports whether the given ISO 3166-1 alpha-2 country code is an EU member.
func IsEUMember(iso string) bool {
	return euMembers[iso]
}

func (g *geoip) Country(ip net.IP) (Country, error) {
	country := Country{}
	if g.country == nil {
		return country, nil
	}
	var record countryRecord
	if err := g.country.Lookup(ip, &record); err != nil {
		return country, err
	}
	country.ISO = record.CountryCode
	// Resolve the full country name from a static ISO 3166-1 alpha-2 table —
	// the MMDB source (AI.md PART 19) exposes only country_code, no name.
	if country.ISO != "" {
		country.Name = iso3166Names[country.ISO]
		isEU := IsEUMember(country.ISO)
		country.IsEU = &isEU
	}
	return country, nil
}

func (g *geoip) City(ip net.IP) (City, error) {
	city := City{}
	reader := g.cityV6
	if ip.To4() != nil {
		reader = g.cityV4
	}
	if reader == nil {
		return city, nil
	}
	var record cityRecord
	if err := reader.Lookup(ip, &record); err != nil {
		return city, err
	}
	city.Name = record.City
	city.RegionName = record.State1
	if !math.IsNaN(record.Latitude) {
		city.Latitude = record.Latitude
	}
	if !math.IsNaN(record.Longitude) {
		city.Longitude = record.Longitude
	}
	city.PostalCode = record.Postcode
	city.Timezone = record.Timezone
	return city, nil
}

func (g *geoip) ASN(ip net.IP) (ASN, error) {
	asn := ASN{}
	if g.asn == nil {
		return asn, nil
	}
	var record asnRecord
	if err := g.asn.Lookup(ip, &record); err != nil {
		return asn, err
	}
	if record.ASN > 0 {
		asn.AutonomousSystemNumber = uint(record.ASN)
	}
	asn.AutonomousSystemOrganization = record.Org
	return asn, nil
}

func (g *geoip) IsEmpty() bool {
	return g.country == nil && g.cityV4 == nil && g.cityV6 == nil
}
