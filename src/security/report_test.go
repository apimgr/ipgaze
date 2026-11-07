package security

import (
	"strings"
	"testing"
	"time"
)

func TestSanitizeReportComponent(t *testing.T) {
	if got := SanitizeReportComponent("  api\n\x00gateway  "); got != "apigateway" {
		t.Errorf("SanitizeReportComponent() = %q, want control characters removed", got)
	}
	long := strings.Repeat("界", 121)
	if got := SanitizeReportComponent(long); got != strings.Repeat("界", 120) {
		t.Errorf("SanitizeReportComponent() rune length = %d, want 120", len([]rune(got)))
	}
}

func TestStoreSecurityReportRejectsInvalidInput(t *testing.T) {
	if err := StoreSecurityReport(nil, SecurityReportMetadata{}); err == nil {
		t.Fatal("StoreSecurityReport(nil) succeeded")
	}
	db := openMemDB(t)
	defer db.Close()
	if err := StoreSecurityReport(db, SecurityReportMetadata{TrackingID: "sec_invalid", Ciphertext: []byte("encrypted"), Severity: "HIGH"}); err == nil {
		t.Fatal("StoreSecurityReport accepted invalid severity and empty encryption metadata")
	}
}

func TestReencryptSecurityReports(t *testing.T) {
	db := openMemDB(t)
	defer db.Close()
	oldKey := []byte("01234567890123456789012345678901")
	newKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	plain := []byte("private report body")
	ciphertext, err := EncryptWithSecret(oldKey, plain, "security-reports")
	if err != nil {
		t.Fatal(err)
	}
	if err := StoreSecurityReport(db, SecurityReportMetadata{
		TrackingID: "sec_rotation", Ciphertext: ciphertext, Encryption: "aes-256-gcm", Severity: "high",
	}); err != nil {
		t.Fatal(err)
	}
	if err := ReencryptSecurityReports(db, oldKey, newKey); err != nil {
		t.Fatal(err)
	}
	var rotated []byte
	if err := db.QueryRow(`SELECT encrypted_body FROM security_reports WHERE tracking_id = ?`, "sec_rotation").Scan(&rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptWithSecret(oldKey, rotated, "security-reports"); err == nil {
		t.Fatal("report remained decryptable with old key")
	}
	decrypted, err := DecryptWithSecret(newKey, rotated, "security-reports")
	if err != nil || string(decrypted) != string(plain) {
		t.Fatalf("rotated report decrypt = %q, %v", decrypted, err)
	}
	if err := ReencryptSecurityReports(db, oldKey, newKey); err == nil {
		t.Fatal("rotation accepted a report that could not be decrypted with the old key")
	}
}

func TestUpdateSecurityReportTriage(t *testing.T) {
	db := openMemDB(t)
	defer db.Close()
	if err := StoreSecurityReport(db, SecurityReportMetadata{
		TrackingID: "sec_triage", Ciphertext: []byte("encrypted"), Encryption: "aes-256-gcm", Severity: "high",
	}); err != nil {
		t.Fatal(err)
	}
	disclosure := time.Date(2027, time.February, 3, 0, 0, 0, 0, time.UTC)
	closed := time.Date(2027, time.February, 3, 12, 0, 0, 0, time.UTC)
	if err := UpdateSecurityReportTriage(db, "sec_triage", "Disclosed", "  Fix released\x00\nThank you. ", &disclosure, closed); err != nil {
		t.Fatal(err)
	}
	var status, comment string
	var disclosedYear int
	var disclosureUnix, closedUnix int64
	if err := db.QueryRow(`SELECT status, maintainer_comment, disclosed_year, disclosure_date, closed_at FROM security_reports WHERE tracking_id = ?`, "sec_triage").Scan(&status, &comment, &disclosedYear, &disclosureUnix, &closedUnix); err != nil {
		t.Fatal(err)
	}
	if status != "Disclosed" || comment != "Fix released\nThank you." || disclosedYear != 2027 || disclosureUnix != disclosure.Unix() || closedUnix != closed.Unix() {
		t.Errorf("triage row = (%q, %q, %d, %d, %d), unexpected values", status, comment, disclosedYear, disclosureUnix, closedUnix)
	}
	if err := UpdateSecurityReportTriage(db, "sec_triage", "Unknown", "", nil, closed); err == nil {
		t.Fatal("invalid report status was accepted")
	}
	if err := UpdateSecurityReportTriage(db, "sec_missing", "Received", "", nil, closed); err == nil {
		t.Fatal("unknown report ID was accepted")
	}
}

func TestValidateSecurityIDWindowsAndRotation(t *testing.T) {
	now := time.Unix(4*securityIDWindow+123, 0)
	current := []byte("current installation secret")
	previous := []byte("previous installation secret")
	cases := []struct {
		name      string
		candidate string
		want      bool
	}{
		{name: "current window", candidate: SecurityID(current, now.Unix()), want: true},
		{name: "previous window", candidate: SecurityID(current, now.Add(-time.Duration(securityIDWindow)*time.Second).Unix()), want: true},
		{name: "previous rotated secret", candidate: SecurityID(previous, now.Unix()), want: true},
		{name: "older window rejected", candidate: SecurityID(current, now.Add(-2*time.Duration(securityIDWindow)*time.Second).Unix()), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidateSecurityID(current, previous, tc.candidate, now); got != tc.want {
				t.Errorf("ValidateSecurityID() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestSecurityReportTokenOneUsePerDay(t *testing.T) {
	db := openMemDB(t)
	defer db.Close()
	ciphertext, err := EncryptWithSecret([]byte("01234567890123456789012345678901"), []byte("encrypted report"), "security-reports")
	if err != nil {
		t.Fatal(err)
	}
	trackingID, err := NewSecurityTrackingID()
	if err != nil {
		t.Fatal(err)
	}
	token, tokenHash, err := NewSecurityAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := StoreSecurityReport(db, SecurityReportMetadata{
		TrackingID: trackingID, Ciphertext: ciphertext, Encryption: "aes-256-gcm",
		Severity: "high", AffectedComponent: "api", CreditPreference: "anonymous",
		AccessTokenHash: tokenHash,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 6, 12, 0, 0, 0, time.UTC)
	status, err := ConsumeSecurityAccessToken(db, trackingID, token, now)
	if err != nil || status.Status != "Received" {
		t.Fatalf("first status access = (%#v, %v), want Received", status, err)
	}
	if _, err := ConsumeSecurityAccessToken(db, trackingID, token, now.Add(time.Hour)); err == nil {
		t.Fatal("same-day token reuse succeeded")
	}
	if _, err := ConsumeSecurityAccessToken(db, trackingID, token, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("next-day token access failed: %v", err)
	}
}
