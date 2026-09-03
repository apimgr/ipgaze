package geo

import (
	"net"
	"testing"
)

// ─────────────────────── IsEUMember ──────────────────────────────────────────

// All 27 current EU member states must be recognised.
func TestIsEUMember_AllCurrentMembers(t *testing.T) {
	members := []string{
		"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE",
		"ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT",
		"LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO",
		"SE", "SI", "SK",
	}
	if len(members) != 27 {
		t.Fatalf("test data error: expected 27 EU members, got %d", len(members))
	}
	for _, iso := range members {
		if !IsEUMember(iso) {
			t.Errorf("IsEUMember(%q): got false, want true", iso)
		}
	}
}

// Non-EU countries must return false.
func TestIsEUMember_NonMembers(t *testing.T) {
	nonMembers := []string{
		"US", "GB", "CH", "NO", "IS", "TR", "UA", "RU",
		"CN", "JP", "AU", "CA", "BR", "IN", "ZA", "MX",
		// Empty string must not match.
		"",
	}
	for _, iso := range nonMembers {
		if IsEUMember(iso) {
			t.Errorf("IsEUMember(%q): got true, want false", iso)
		}
	}
}

// IsEUMember is case-sensitive — lowercase codes must not match.
func TestIsEUMember_CaseSensitive(t *testing.T) {
	if IsEUMember("de") {
		t.Error("IsEUMember(\"de\"): got true, want false (should be case-sensitive)")
	}
	if IsEUMember("fr") {
		t.Error("IsEUMember(\"fr\"): got true, want false (should be case-sensitive)")
	}
}

// GB left the EU (Brexit 2020-01-31) — must not be a member.
func TestIsEUMember_GBNotMember(t *testing.T) {
	if IsEUMember("GB") {
		t.Error("IsEUMember(\"GB\"): got true, want false (UK left the EU)")
	}
}

// ─────────────────────── Open — empty paths ───────────────────────────────────

// Open with all empty paths must succeed and return a non-nil Reader.
func TestOpen_AllEmptyPaths_Success(t *testing.T) {
	r, err := Open("", "", "", "")
	if err != nil {
		t.Fatalf("Open(\"\",\"\",\"\",\"\"): unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("Open(\"\",\"\",\"\",\"\"): returned nil Reader")
	}
}

// Open with all empty paths must report IsEmpty() == true.
func TestOpen_AllEmptyPaths_IsEmpty(t *testing.T) {
	r, _ := Open("", "", "", "")
	if !r.IsEmpty() {
		t.Error("Open(\"\",\"\",\"\",\"\").IsEmpty(): got false, want true")
	}
}

// Open with a non-existent DB path must return an error.
func TestOpen_NonExistentPath_ReturnsError(t *testing.T) {
	_, err := Open("/nonexistent/country.mmdb", "", "", "")
	if err == nil {
		t.Error("Open(non-existent country DB): expected error, got nil")
	}
}

func TestOpen_NonExistentCityPath_ReturnsError(t *testing.T) {
	_, err := Open("", "/nonexistent/city.mmdb", "", "")
	if err == nil {
		t.Error("Open(non-existent city DB): expected error, got nil")
	}
}

func TestOpen_NonExistentASNPath_ReturnsError(t *testing.T) {
	_, err := Open("", "", "", "/nonexistent/asn.mmdb")
	if err == nil {
		t.Error("Open(non-existent ASN DB): expected error, got nil")
	}
}

// ─────────────────────── Reader with nil DBs — nil-safe paths ─────────────────

// Country() with nil country DB must return an empty Country and no error.
func TestGeoip_Country_NilDB_ReturnsEmpty(t *testing.T) {
	r, err := Open("", "", "", "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	c, err := r.Country(net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Errorf("Country() with nil DB: unexpected error: %v", err)
	}
	if c.ISO != "" {
		t.Errorf("Country() with nil DB: got ISO=%q, want empty string", c.ISO)
	}
	if c.IsEU != nil {
		t.Errorf("Country() with nil DB: got IsEU=%v, want nil", c.IsEU)
	}
}

// City() with nil city DB must return an empty City and no error.
func TestGeoip_City_NilDB_ReturnsEmpty(t *testing.T) {
	r, err := Open("", "", "", "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	city, err := r.City(net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Errorf("City() with nil DB: unexpected error: %v", err)
	}
	if city.Name != "" {
		t.Errorf("City() with nil DB: got Name=%q, want empty", city.Name)
	}
}

// ASN() with nil ASN DB must return an empty ASN and no error.
func TestGeoip_ASN_NilDB_ReturnsEmpty(t *testing.T) {
	r, err := Open("", "", "", "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	asn, err := r.ASN(net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Errorf("ASN() with nil DB: unexpected error: %v", err)
	}
	if asn.AutonomousSystemNumber != 0 {
		t.Errorf("ASN() with nil DB: got ASN=%d, want 0", asn.AutonomousSystemNumber)
	}
	if asn.AutonomousSystemOrganization != "" {
		t.Errorf("ASN() with nil DB: got Org=%q, want empty", asn.AutonomousSystemOrganization)
	}
}

// ─────────────────────── IsEmpty semantics ───────────────────────────────────

// IsEmpty is defined as country==nil && cityV4==nil && cityV6==nil.
// Opening with only an ASN path (impossible to test without a real file) would
// leave IsEmpty() false; we can only exercise the fully-nil case here.
func TestGeoip_IsEmpty_AllNil_True(t *testing.T) {
	r, _ := Open("", "", "", "")
	if !r.IsEmpty() {
		t.Error("geoip.IsEmpty(): all nil DBs should be empty")
	}
}

// ─────────────────────── Country EU-membership tagging ───────────────────────

// When the country ISO code is a known EU member, Country() must set IsEU to a
// non-nil *bool pointing to true. We cannot call a real MMDB here, so we test
// the helper logic directly through the exported IsEUMember function and verify
// that both sides of the branch work correctly.
func TestIsEUMember_FranceIsEU(t *testing.T) {
	if !IsEUMember("FR") {
		t.Error("IsEUMember(\"FR\"): got false, want true")
	}
	isEU := IsEUMember("FR")
	if !isEU {
		t.Error("IsEUMember(\"FR\"): want true pointer value")
	}
}

func TestIsEUMember_USIsNotEU(t *testing.T) {
	isEU := IsEUMember("US")
	if isEU {
		t.Error("IsEUMember(\"US\"): got true, want false")
	}
}

// ─────────────────────── Struct field zero values ────────────────────────────

// Country zero value must have nil IsEU pointer so callers can distinguish
// "not looked up" from "looked up and not EU".
func TestCountry_ZeroValue_IsEUNil(t *testing.T) {
	var c Country
	if c.IsEU != nil {
		t.Errorf("Country zero value: IsEU should be nil, got %v", c.IsEU)
	}
}

func TestASN_ZeroValue(t *testing.T) {
	var a ASN
	if a.AutonomousSystemNumber != 0 {
		t.Errorf("ASN zero value: Number=%d, want 0", a.AutonomousSystemNumber)
	}
	if a.AutonomousSystemOrganization != "" {
		t.Errorf("ASN zero value: Org=%q, want empty", a.AutonomousSystemOrganization)
	}
}
