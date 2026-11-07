package security

import (
	"bytes"
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
	defer func() { _ = db.Close() }()
	if err := StoreSecurityReport(db, SecurityReportMetadata{TrackingID: "sec_invalid", Ciphertext: []byte("encrypted"), Severity: "HIGH"}); err == nil {
		t.Fatal("StoreSecurityReport accepted invalid severity and empty encryption metadata")
	}
	if err := StoreSecurityReport(db, SecurityReportMetadata{
		TrackingID: "sec_plain_credit", Ciphertext: []byte("encrypted"), Encryption: "aes-256-gcm",
		Severity: "high", CreditName: "Private Reporter",
	}); err == nil {
		t.Fatal("StoreSecurityReport accepted plaintext researcher credit")
	}
}

func TestSecurityCreditEncryptionAndLegacyMigration(t *testing.T) {
	db := openMemDB(t)
	defer func() { _ = db.Close() }()
	key := bytes.Repeat([]byte{7}, 32)
	encrypted, err := EncryptSecurityCredit(key, "Researcher Name")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encrypted, "Researcher Name") {
		t.Fatal("encrypted credit contains the plaintext name")
	}
	decrypted, err := DecryptSecurityCredit(key, encrypted)
	if err != nil || decrypted != "Researcher Name" {
		t.Fatalf("DecryptSecurityCredit() = %q, %v", decrypted, err)
	}
	if _, err := DecryptSecurityCredit(key, "Researcher Name"); err == nil {
		t.Fatal("DecryptSecurityCredit accepted a plaintext legacy value")
	}
	if err := StoreSecurityReport(db, SecurityReportMetadata{
		TrackingID: "sec_legacy_credit", Ciphertext: []byte("encrypted"), Encryption: "aes-256-gcm",
		Severity: "high", CreditPreference: "real_name", CreditName: "Legacy Name",
	}); err == nil {
		t.Fatal("StoreSecurityReport accepted a plaintext legacy credit")
	}
	if _, err := db.Exec(`INSERT INTO security_reports
		(tracking_id, encrypted_body, encryption, severity, affected_component,
		 credit_preference, credit_name, access_token_hash)
		VALUES ('sec_legacy_credit', 'encrypted', 'aes-256-gcm', 'high', 'api',
		 'real_name', 'Legacy Name', 'token')`); err != nil {
		t.Fatal(err)
	}
	if err := EncryptLegacySecurityCredits(db, key); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRow(`SELECT credit_name FROM security_reports WHERE tracking_id = ?`, "sec_legacy_credit").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "Legacy Name") {
		t.Fatalf("legacy credit remains in plaintext: %q", stored)
	}
	decrypted, err = DecryptSecurityCredit(key, stored)
	if err != nil || decrypted != "Legacy Name" {
		t.Fatalf("migrated credit decrypt = %q, %v", decrypted, err)
	}
	if _, err := db.Exec(`INSERT INTO security_reports
		(tracking_id, encrypted_body, encryption, severity, affected_component,
		 credit_preference, credit_name, access_token_hash)
		VALUES ('sec_invalid_credit', 'encrypted', 'aes-256-gcm', 'high', 'api',
		 'real_name', 'enc:v1:invalid', 'token')`); err != nil {
		t.Fatal(err)
	}
	if err := EncryptLegacySecurityCredits(db, key); err == nil {
		t.Fatal("legacy migration accepted a malformed encrypted credit")
	}
	var malformed string
	if err := db.QueryRow(`SELECT credit_name FROM security_reports WHERE tracking_id = ?`, "sec_invalid_credit").Scan(&malformed); err != nil {
		t.Fatal(err)
	}
	if malformed != "enc:v1:invalid" {
		t.Fatalf("malformed encrypted credit changed during migration: %q", malformed)
	}
}

func TestReencryptSecurityReports(t *testing.T) {
	db := openMemDB(t)
	defer func() { _ = db.Close() }()
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)
	plain := []byte("private report body")
	ciphertext, err := EncryptWithSecret(oldKey, plain, "security-reports")
	if err != nil {
		t.Fatal(err)
	}
	credit, err := EncryptSecurityCredit(oldKey, "Researcher")
	if err != nil {
		t.Fatal(err)
	}
	if err := StoreSecurityReport(db, SecurityReportMetadata{
		TrackingID: "sec_rotation", Ciphertext: ciphertext, Encryption: "aes-256-gcm", Severity: "high",
		CreditPreference: "real_name", CreditName: credit,
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
	var rotatedCredit string
	if err := db.QueryRow(`SELECT credit_name FROM security_reports WHERE tracking_id = ?`, "sec_rotation").Scan(&rotatedCredit); err != nil {
		t.Fatal(err)
	}
	decryptedCredit, err := DecryptSecurityCredit(newKey, rotatedCredit)
	if err != nil || decryptedCredit != "Researcher" {
		t.Fatalf("rotated credit decrypt = %q, %v", decryptedCredit, err)
	}
	if _, err := DecryptSecurityCredit(oldKey, rotatedCredit); err == nil {
		t.Fatal("rotated credit remained decryptable with old key")
	}
	if err := ReencryptSecurityReports(db, oldKey, newKey); err == nil {
		t.Fatal("rotation accepted a report that could not be decrypted with the old key")
	}
}

func TestUpdateSecurityReportTriage(t *testing.T) {
	db := openMemDB(t)
	defer func() { _ = db.Close() }()
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
	defer func() { _ = db.Close() }()
	ciphertext, err := EncryptWithSecret(bytes.Repeat([]byte{3}, 32), []byte("encrypted report"), "security-reports")
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
