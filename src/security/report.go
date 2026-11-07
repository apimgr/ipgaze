package security

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const securityIDWindow = int64(48 * time.Hour / time.Second)

const securityCreditPrefix = "enc:v1:"

// SecurityID returns the rotating security.txt token for the current 48-hour
// window. The output is deliberately short because it is published in a URL.
func SecurityID(secret []byte, unixSeconds int64) string {
	window := unixSeconds / securityIDWindow
	mac := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(mac, "%d", window)
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// CurrentSecurityID loads the persisted installation secret and computes the
// token for the current 48-hour window.
func CurrentSecurityID(db *sql.DB, now time.Time) (string, error) {
	secret, err := GetOrCreateSecret(db, SecretInstallationSecret)
	if err != nil {
		return "", err
	}
	return SecurityID(secret, now.Unix()), nil
}

// IsValidSecurityID validates a published token against current and live
// previous installation secrets.
func IsValidSecurityID(db *sql.DB, candidate string, now time.Time) (bool, error) {
	current, err := GetOrCreateSecret(db, SecretInstallationSecret)
	if err != nil {
		return false, err
	}
	previous, err := PreviousSecret(db, SecretInstallationSecret)
	if err != nil {
		return false, err
	}
	return ValidateSecurityID(current, previous, candidate, now), nil
}

// ValidateSecurityID accepts the current and previous window for both the
// current secret and the live rotation grace secret.
func ValidateSecurityID(current, previous []byte, candidate string, now time.Time) bool {
	if len(candidate) != 16 {
		return false
	}
	var match byte
	for _, secret := range [][]byte{current, previous} {
		if len(secret) == 0 {
			continue
		}
		for delta := int64(0); delta <= 1; delta++ {
			want := SecurityID(secret, now.Unix()-delta*securityIDWindow)
			if hmac.Equal([]byte(want), []byte(candidate)) {
				match = 1
			}
		}
	}
	return match != 0
}

// NewSecurityTrackingID creates the opaque public identifier for a report.
func NewSecurityTrackingID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("security: generate report id: %w", err)
	}
	return "sec_" + hex.EncodeToString(raw), nil
}

// NewSecurityAccessToken creates an opaque URL token and its database hash.
func NewSecurityAccessToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("security: generate report access token: %w", err)
	}
	token := hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(hash[:]), nil
}

// SecurityReportMetadata is the unencrypted, non-identifying report state.
type SecurityReportMetadata struct {
	TrackingID        string
	Ciphertext        []byte
	Encryption        string
	Severity          string
	AffectedComponent string
	CreditPreference  string
	// CreditName is encrypted with the server data key.
	CreditName      string
	ShortCredit     string
	AccessTokenHash string
}

// EncryptSecurityCredit protects a consented researcher name or handle while
// it remains private in the report database. The public acknowledgment page
// decrypts it only after the report is marked disclosed.
func EncryptSecurityCredit(secret []byte, name string) (string, error) {
	if name == "" {
		return "", nil
	}
	ciphertext, err := EncryptWithSecret(secret, []byte(name), "security-report-credit")
	if err != nil {
		return "", fmt.Errorf("security: encrypt researcher credit: %w", err)
	}
	return securityCreditPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSecurityCredit decrypts a researcher credit for a report that is
// already public. Plaintext legacy values are rejected and never rendered.
func DecryptSecurityCredit(secret []byte, stored string) (string, error) {
	if !strings.HasPrefix(stored, securityCreditPrefix) {
		return "", errors.New("security: researcher credit is not encrypted")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, securityCreditPrefix))
	if err != nil {
		return "", fmt.Errorf("security: decode researcher credit: %w", err)
	}
	plaintext, err := DecryptWithSecret(secret, ciphertext, "security-report-credit")
	if err != nil {
		return "", fmt.Errorf("security: decrypt researcher credit: %w", err)
	}
	return string(plaintext), nil
}

// EncryptLegacySecurityCredits upgrades pre-encryption credit names in place.
// Startup calls this before serving requests so existing names are not left
// in plaintext at rest.
func EncryptLegacySecurityCredits(db *sql.DB, secret []byte) error {
	if db == nil || len(secret) == 0 {
		return errors.New("security: invalid researcher-credit migration input")
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("security: begin researcher-credit migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(`SELECT tracking_id, credit_name FROM security_reports WHERE credit_name != ''`)
	if err != nil {
		return fmt.Errorf("security: read legacy researcher credits: %w", err)
	}
	type legacyCredit struct{ trackingID, name string }
	var credits []legacyCredit
	for rows.Next() {
		var credit legacyCredit
		if err := rows.Scan(&credit.trackingID, &credit.name); err != nil {
			_ = rows.Close()
			return fmt.Errorf("security: read legacy researcher credit: %w", err)
		}
		credits = append(credits, credit)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("security: iterate legacy researcher credits: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("security: close legacy researcher credits: %w", err)
	}
	for _, credit := range credits {
		if strings.HasPrefix(credit.name, securityCreditPrefix) {
			if _, err := DecryptSecurityCredit(secret, credit.name); err != nil {
				return fmt.Errorf("security: existing researcher credit cannot be decrypted: %w", err)
			}
			continue
		}
		encrypted, err := EncryptSecurityCredit(secret, credit.name)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE security_reports SET credit_name = ? WHERE tracking_id = ?`, encrypted, credit.trackingID); err != nil {
			return fmt.Errorf("security: encrypt legacy researcher credit: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("security: commit researcher-credit migration: %w", err)
	}
	return nil
}

// StoreSecurityReport stores encrypted report content and non-identifying
// triage metadata. Names, email addresses, URLs, and report details belong in
// Ciphertext; CreditName is separately encrypted with the server data key.
func StoreSecurityReport(db *sql.DB, report SecurityReportMetadata) error {
	if db == nil {
		return errors.New("security: report database unavailable")
	}
	if !validSecuritySeverity(report.Severity) || report.TrackingID == "" || len(report.Ciphertext) == 0 {
		return errors.New("security: invalid report metadata")
	}
	if report.CreditName != "" && !strings.HasPrefix(report.CreditName, securityCreditPrefix) {
		return errors.New("security: researcher credit must be encrypted")
	}
	component := SanitizeReportComponent(report.AffectedComponent)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, `INSERT INTO security_reports
		(tracking_id, encrypted_body, encryption, severity, affected_component,
		 credit_preference, credit_name, short_credit, access_token_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, report.TrackingID, report.Ciphertext, report.Encryption,
		report.Severity, component, report.CreditPreference, report.CreditName,
		report.ShortCredit, report.AccessTokenHash)
	if err != nil {
		return fmt.Errorf("security: store report: %w", err)
	}
	return nil
}

// ReencryptSecurityReports rotates AES-encrypted report bodies in one
// transaction. PGP-encrypted reports are unaffected by the server AES key.
func ReencryptSecurityReports(db *sql.DB, oldKey, newKey []byte) error {
	if db == nil || len(oldKey) != 32 || len(newKey) != 32 {
		return errors.New("security: invalid report encryption rotation input")
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("security: begin report key rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := ReencryptSecurityReportsTx(tx, oldKey, newKey); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("security: commit report key rotation: %w", err)
	}
	return nil
}

// ReencryptSecurityReportsTx performs report re-encryption inside a caller's
// transaction so configuration and database changes can be coordinated.
func ReencryptSecurityReportsTx(tx *sql.Tx, oldKey, newKey []byte) error {
	if tx == nil || len(oldKey) != 32 || len(newKey) != 32 {
		return errors.New("security: invalid report encryption rotation input")
	}
	rows, err := tx.Query(`SELECT tracking_id, encrypted_body FROM security_reports WHERE encryption = 'aes-256-gcm'`)
	if err != nil {
		return fmt.Errorf("security: read reports for key rotation: %w", err)
	}
	type encryptedReport struct {
		trackingID string
		ciphertext []byte
	}
	var reports []encryptedReport
	for rows.Next() {
		var report encryptedReport
		if err := rows.Scan(&report.trackingID, &report.ciphertext); err != nil {
			_ = rows.Close()
			return fmt.Errorf("security: scan report for key rotation: %w", err)
		}
		reports = append(reports, report)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("security: iterate reports for key rotation: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("security: close reports for key rotation: %w", err)
	}
	for _, report := range reports {
		plain, err := DecryptWithSecret(oldKey, report.ciphertext, "security-reports")
		if err != nil {
			return fmt.Errorf("security: decrypt report %s during key rotation: %w", report.trackingID, err)
		}
		ciphertext, err := EncryptWithSecret(newKey, plain, "security-reports")
		if err != nil {
			return fmt.Errorf("security: encrypt report %s during key rotation: %w", report.trackingID, err)
		}
		if _, err := tx.Exec(`UPDATE security_reports SET encrypted_body = ? WHERE tracking_id = ?`, ciphertext, report.trackingID); err != nil {
			return fmt.Errorf("security: update report %s during key rotation: %w", report.trackingID, err)
		}
	}
	creditRows, err := tx.Query(`SELECT tracking_id, credit_name FROM security_reports
		WHERE credit_name != '' AND credit_name LIKE ?`, securityCreditPrefix+"%")
	if err != nil {
		return fmt.Errorf("security: read credits for key rotation: %w", err)
	}
	type encryptedCredit struct{ trackingID, ciphertext string }
	var credits []encryptedCredit
	for creditRows.Next() {
		var credit encryptedCredit
		if err := creditRows.Scan(&credit.trackingID, &credit.ciphertext); err != nil {
			_ = creditRows.Close()
			return fmt.Errorf("security: read credit for key rotation: %w", err)
		}
		credits = append(credits, credit)
	}
	if err := creditRows.Err(); err != nil {
		_ = creditRows.Close()
		return fmt.Errorf("security: iterate credits for key rotation: %w", err)
	}
	if err := creditRows.Close(); err != nil {
		return fmt.Errorf("security: close credits for key rotation: %w", err)
	}
	for _, credit := range credits {
		name, err := DecryptSecurityCredit(oldKey, credit.ciphertext)
		if err != nil {
			return fmt.Errorf("security: decrypt credit for key rotation: %w", err)
		}
		encrypted, err := EncryptSecurityCredit(newKey, name)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE security_reports SET credit_name = ? WHERE tracking_id = ?`, encrypted, credit.trackingID); err != nil {
			return fmt.Errorf("security: rotate encrypted credit: %w", err)
		}
	}
	return nil
}

// UpdateSecurityReportTriage changes only the public triage fields; encrypted
// report content is never exposed through this maintenance operation.
func UpdateSecurityReportTriage(db *sql.DB, trackingID, status, comment string, disclosureDate *time.Time, now time.Time) error {
	if db == nil || strings.TrimSpace(trackingID) == "" || !validSecurityReportStatus(status) {
		return errors.New("security: invalid report triage update")
	}
	comment = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(comment))
	if len([]rune(comment)) > 2000 {
		return errors.New("security: maintainer comment exceeds 2000 characters")
	}
	var disclosure any
	var disclosedYear any
	if disclosureDate != nil {
		date := disclosureDate.UTC()
		disclosure = date.Unix()
		if status == "Disclosed" {
			disclosedYear = date.Year()
		}
	}
	var closed any
	if status == "Disclosed" || status == "Won't Fix" {
		closed = now.UTC().Unix()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := db.ExecContext(ctx, `UPDATE security_reports SET status = ?, maintainer_comment = ?,
		disclosure_date = ?, closed_at = ?, disclosed_year = ? WHERE tracking_id = ?`,
		status, comment, disclosure, closed, disclosedYear, trackingID)
	if err != nil {
		return fmt.Errorf("security: update report triage: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("security: confirm report triage update: %w", err)
	}
	if updated != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func validSecurityReportStatus(status string) bool {
	switch status {
	case "Received", "Triaged", "Confirmed", "Patching", "Disclosed", "Won't Fix":
		return true
	default:
		return false
	}
}

// SecurityReportStatus is the public subset displayed to the report owner.
type SecurityReportStatus struct {
	TrackingID        string
	Status            string
	MaintainerComment string
	DisclosureDate    *time.Time
	ClosedAt          *time.Time
}

// ConsumeSecurityAccessToken validates a report token and permits one access
// per UTC day. A closed report remains accessible for 30 days.
func ConsumeSecurityAccessToken(db *sql.DB, trackingID, token string, now time.Time) (SecurityReportStatus, error) {
	var status SecurityReportStatus
	var hash string
	var lastAccessDay sql.NullInt64
	var disclosure, closed sql.NullInt64
	var comment sql.NullString
	readCtx, cancelRead := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelRead()
	err := db.QueryRowContext(readCtx, `SELECT tracking_id, status, maintainer_comment, disclosure_date,
		closed_at, access_token_hash, last_access_day FROM security_reports WHERE tracking_id = ?`, trackingID).
		Scan(&status.TrackingID, &status.Status, &comment, &disclosure, &closed, &hash, &lastAccessDay)
	if err != nil {
		return SecurityReportStatus{}, err
	}
	suppliedHash := sha256.Sum256([]byte(token))
	if !hmac.Equal([]byte(hash), []byte(hex.EncodeToString(suppliedHash[:]))) {
		return SecurityReportStatus{}, errors.New("security: invalid report access token")
	}
	day := now.UTC().Unix() / 86400
	if lastAccessDay.Valid && lastAccessDay.Int64 >= day {
		return SecurityReportStatus{}, errors.New("security: report token already used today")
	}
	if closed.Valid && now.Unix() > closed.Int64+int64(30*24*time.Hour/time.Second) {
		return SecurityReportStatus{}, errors.New("security: report access expired")
	}
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelWrite()
	result, err := db.ExecContext(writeCtx, `UPDATE security_reports SET last_access_day = ?
		WHERE tracking_id = ? AND (last_access_day IS NULL OR last_access_day < ?)`, day, trackingID, day)
	if err != nil {
		return SecurityReportStatus{}, fmt.Errorf("security: consume report token: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return SecurityReportStatus{}, fmt.Errorf("security: confirm report token use: %w", err)
	}
	if n != 1 {
		return SecurityReportStatus{}, errors.New("security: report token already used today")
	}
	if comment.Valid {
		status.MaintainerComment = comment.String
	}
	if disclosure.Valid {
		t := time.Unix(disclosure.Int64, 0).UTC()
		status.DisclosureDate = &t
	}
	if closed.Valid {
		t := time.Unix(closed.Int64, 0).UTC()
		status.ClosedAt = &t
	}
	return status, nil
}

func validSecuritySeverity(value string) bool {
	switch value {
	case "critical", "high", "medium", "low", "informational":
		return true
	default:
		return false
	}
}

func SanitizeReportComponent(value string) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if utf8.RuneCountInString(value) > 120 {
		runes := []rune(value)
		value = string(runes[:120])
	}
	return value
}
