package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/apimgr/ipgaze/src/security"
	"github.com/google/uuid"
)

const ownerTokenEncryptionInfo = "api_tokens"
const ownerTokenFlashCookieName = "owner_token_flash"

var errPrimaryOwnerTokenRequired = errors.New("primary owner token required")
var errInsufficientTokenScope = errors.New("insufficient token scope")

const (
	OwnerTokenScopeRead      = "read"
	OwnerTokenScopeReadWrite = "read-write"
	OwnerTokenScopeGlobal    = "global"
)

const ownerTokenAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func ownerTokenPrefix(token string) string {
	if len(token) <= 12 {
		return token
	}
	return token[:12]
}

type OwnerTokenIdentity struct {
	OwnerID   string
	TokenID   string
	Kind      string
	Scope     string
	Prefix    string
	Last4     string
	Encrypted string
	TokenHash string
}

type ownerTokenFlash struct {
	Token  string `json:"token"`
	Action string `json:"action"`
	ID     string `json:"id,omitempty"`
}

func (h *PagesHandler) setOwnerTokenFlash(w http.ResponseWriter, r *http.Request, flash ownerTokenFlash) error {
	key, err := h.ownerTokenKey()
	if err != nil {
		return err
	}
	plain, err := json.Marshal(flash)
	if err != nil {
		return err
	}
	ciphertext, err := security.EncryptWithSecret(key, plain, ownerTokenFlashCookieName)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: ownerTokenFlashCookieName, Value: base64.RawURLEncoding.EncodeToString(ciphertext), Path: "/server/preferences/tokens", MaxAge: 60, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	return nil
}

func (h *PagesHandler) consumeOwnerTokenFlash(w http.ResponseWriter, r *http.Request) ownerTokenFlash {
	http.SetCookie(w, &http.Cookie{Name: ownerTokenFlashCookieName, Value: "", Path: "/server/preferences/tokens", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	cookie, err := r.Cookie(ownerTokenFlashCookieName)
	if err != nil {
		return ownerTokenFlash{}
	}
	key, err := h.ownerTokenKey()
	if err != nil {
		return ownerTokenFlash{}
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return ownerTokenFlash{}
	}
	plain, err := security.DecryptWithSecret(key, ciphertext, ownerTokenFlashCookieName)
	if err != nil {
		return ownerTokenFlash{}
	}
	var flash ownerTokenFlash
	if json.Unmarshal(plain, &flash) != nil || !validOwnerPrimaryToken(flash.Token) {
		return ownerTokenFlash{}
	}
	return flash
}

type OwnerLinkedTokenView struct {
	ID        string
	Name      string
	Scope     string
	Masked    string
	Created   string
	LastUsed  string
	Expires   string
	Expiry    string
	ExpiresOn string
	Status    string
}

func bearerTokenFromHeader(r *http.Request) (string, bool) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}

func (h *PagesHandler) ownerTokenKey() ([]byte, error) {
	if h.Config == nil || strings.TrimSpace(h.Config.Server.Security.EncryptionKey) == "" {
		return nil, errors.New("owner token encryption is unavailable")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h.Config.Server.Security.EncryptionKey))
	if err != nil || len(key) != 32 {
		return nil, errors.New("owner token encryption is unavailable")
	}
	return key, nil
}

func generateOwnerToken() (string, error) {
	var token strings.Builder
	token.Grow(36)
	token.WriteString("own_")
	for range 32 {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(ownerTokenAlphabet))))
		if err != nil {
			return "", fmt.Errorf("generate owner token: %w", err)
		}
		token.WriteByte(ownerTokenAlphabet[index.Int64()])
	}
	return token.String(), nil
}

func validLinkedTokenScope(scope string) bool {
	return scope == OwnerTokenScopeRead || scope == OwnerTokenScopeReadWrite
}

func (h *PagesHandler) createPrimaryToken(ctx context.Context) (OwnerTokenIdentity, string, error) {
	if h.DB == nil {
		return OwnerTokenIdentity{}, "", errors.New("owner token database is unavailable")
	}
	key, err := h.ownerTokenKey()
	if err != nil {
		return OwnerTokenIdentity{}, "", err
	}
	token, err := generateOwnerToken()
	if err != nil {
		return OwnerTokenIdentity{}, "", err
	}
	ownerID := uuid.NewString()
	hash := sha256.Sum256([]byte(token))
	ciphertext, err := security.EncryptWithSecret(key, []byte(token), ownerTokenEncryptionInfo)
	if err != nil {
		return OwnerTokenIdentity{}, "", fmt.Errorf("encrypt owner token: %w", err)
	}
	tokenUUID, err := uuid.NewV7()
	if err != nil {
		return OwnerTokenIdentity{}, "", fmt.Errorf("generate API token ID: %w", err)
	}
	publicID := tokenUUID.String()
	tokenID := publicID
	err = h.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO owners(id) VALUES(?)`, ownerID); err != nil {
			return err
		}
		if h.DB.APITokenIDColumn() == "public_id" {
			_, err := tx.ExecContext(ctx, `INSERT INTO api_tokens(owner_id, kind, scope, token_hash, token_prefix, token_last4, token_enc, public_id)
				VALUES(?, 'primary', 'global', ?, ?, ?, ?, ?)`, ownerID, hex.EncodeToString(hash[:]), ownerTokenPrefix(token), ownerTokenSuffix(token), base64.StdEncoding.EncodeToString(ciphertext), tokenID)
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO api_tokens(id, owner_id, kind, scope, token_hash, token_prefix, token_last4, token_enc)
			VALUES(?, ?, 'primary', 'global', ?, ?, ?, ?)`, tokenID, ownerID, hex.EncodeToString(hash[:]), ownerTokenPrefix(token), ownerTokenSuffix(token), base64.StdEncoding.EncodeToString(ciphertext))
		return err
	})
	if err != nil {
		return OwnerTokenIdentity{}, "", err
	}
	return OwnerTokenIdentity{OwnerID: ownerID, TokenID: tokenID, Kind: "primary", Scope: OwnerTokenScopeGlobal, Prefix: ownerTokenPrefix(token), Last4: ownerTokenSuffix(token), Encrypted: base64.StdEncoding.EncodeToString(ciphertext)}, token, nil
}

func (h *PagesHandler) validatePrimaryToken(ctx context.Context, token string) (OwnerTokenIdentity, error) {
	if h.DB == nil || !validOwnerPrimaryToken(token) {
		return OwnerTokenIdentity{}, sql.ErrNoRows
	}
	identity, err := h.findOwnerToken(ctx, token, "kind = 'primary'")
	if err == nil {
		h.DB.MarkOwnerUsage(identity.TokenID, identity.OwnerID, time.Now())
	}
	return identity, err
}

func (h *PagesHandler) findOwnerToken(ctx context.Context, token, kindClause string) (identity OwnerTokenIdentity, resultErr error) {
	rows, err := h.DB.QueryContext(ctx, `SELECT `+h.DB.APITokenIDColumn()+`, owner_id, kind, scope, token_hash, token_prefix, token_last4, token_enc
		FROM api_tokens WHERE token_prefix = ? AND owner_id <> 'system' AND `+kindClause+` AND revoked_at IS NULL
		AND (expires_at IS NULL OR expires_at > strftime('%s', 'now'))`, ownerTokenPrefix(token))
	if err != nil {
		return OwnerTokenIdentity{}, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	inboundHash := sha256.Sum256([]byte(token))
	for rows.Next() {
		var storedHash string
		if err := rows.Scan(&identity.TokenID, &identity.OwnerID, &identity.Kind, &identity.Scope, &storedHash, &identity.Prefix, &identity.Last4, &identity.Encrypted); err != nil {
			return OwnerTokenIdentity{}, err
		}
		expectedHash, err := hex.DecodeString(storedHash)
		if err != nil || len(expectedHash) != len(inboundHash) || subtle.ConstantTimeCompare(expectedHash, inboundHash[:]) != 1 {
			continue
		}
		return identity, nil
	}
	if err := rows.Err(); err != nil {
		return OwnerTokenIdentity{}, err
	}
	return OwnerTokenIdentity{}, sql.ErrNoRows
}

func (h *PagesHandler) validatePrimaryBearer(r *http.Request) (OwnerTokenIdentity, error) {
	token, ok := bearerTokenFromHeader(r)
	if !ok {
		if h.TokenRejected != nil {
			h.TokenRejected(r, "")
		}
		return OwnerTokenIdentity{}, sql.ErrNoRows
	}
	identity, err := h.validatePrimaryToken(r.Context(), token)
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		return identity, err
	}
	owner, err := h.validateOwnerBearer(r.Context(), token)
	if err == nil && owner.Scope != OwnerTokenScopeGlobal {
		return OwnerTokenIdentity{}, errInsufficientTokenScope
	}
	if h.TokenRejected != nil {
		h.TokenRejected(r, token)
	}
	return OwnerTokenIdentity{}, sql.ErrNoRows
}

func writePrimaryBearerAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errPrimaryOwnerTokenRequired), errors.Is(err, errInsufficientTokenScope):
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
		SendAPIResponseError(w, http.StatusForbidden, "FORBIDDEN", "A primary owner token is required", nil)
	case errors.Is(err, sql.ErrNoRows):
		SendAPIResponseError(w, http.StatusUnauthorized, "UNAUTHORIZED", "A valid owner token is required", nil)
	default:
		SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to validate owner token", nil)
	}
}

func (h *PagesHandler) ServerPreferencesTokenCreateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if cookie, err := r.Cookie(ownerTokenCookieName); err == nil {
		if _, err := h.validatePrimaryToken(r.Context(), cookie.Value); err == nil {
			http.Redirect(w, r, "/server/preferences/tokens?status=exists", http.StatusSeeOther)
			return
		}
	}
	identity, token, err := h.createPrimaryToken(r.Context())
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=unavailable", http.StatusSeeOther)
		return
	}
	h.setOwnerTokenCookie(w, r, token)
	if h.TokenAuditLogger != nil {
		h.TokenAuditLogger("token.created", "issue", identity.OwnerID, identity.Prefix)
	}
	if h.setOwnerTokenFlash(w, r, ownerTokenFlash{Token: token, Action: "created"}) != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=unavailable", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/server/preferences/tokens#primary", http.StatusSeeOther)
}

func (h *PagesHandler) ownerFromCookie(r *http.Request) (OwnerTokenIdentity, error) {
	cookie, err := r.Cookie(ownerTokenCookieName)
	if err != nil {
		return OwnerTokenIdentity{}, err
	}
	return h.validatePrimaryToken(r.Context(), cookie.Value)
}

func tokenExpiry(value string) (any, error) {
	now := time.Now().Unix()
	switch value {
	case "", "never":
		return nil, nil
	case "7d":
		return now + int64((7 * 24 * time.Hour).Seconds()), nil
	case "30d":
		return now + int64((30 * 24 * time.Hour).Seconds()), nil
	case "90d":
		return now + int64((90 * 24 * time.Hour).Seconds()), nil
	case "1y":
		return now + int64((365 * 24 * time.Hour).Seconds()), nil
	default:
		date, err := time.Parse("2006-01-02", value)
		if err != nil || date.Format("2006-01-02") < time.Now().UTC().Format("2006-01-02") {
			return nil, errors.New("invalid expiry")
		}
		return date.UTC().Add(24*time.Hour - time.Second).Unix(), nil
	}
}

func tokenExpiryForm(r *http.Request) (any, error) {
	value := r.FormValue("expiry")
	if value == "custom" {
		value = r.FormValue("expires_on")
	}
	return tokenExpiry(value)
}

func tokenExpiryAPI(expires, expiresOn string) (any, error) {
	if expires != "" && expiresOn != "" {
		return nil, errors.New("expiry and expires_on are mutually exclusive")
	}
	if expiresOn != "" {
		return tokenExpiry(expiresOn)
	}
	return tokenExpiry(expires)
}

func (h *PagesHandler) ServerPreferencesLinkedTokenCreateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	identity, err := h.ownerFromCookie(r)
	if err != nil || identity.Kind != "primary" {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	if r.ParseForm() != nil {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if nameLength := utf8.RuneCountInString(name); nameLength < 1 || nameLength > 64 {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	scope := strings.TrimSpace(r.FormValue("scope"))
	if scope == "" {
		scope = OwnerTokenScopeReadWrite
	}
	if !validLinkedTokenScope(scope) {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	expires, err := tokenExpiryForm(r)
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	if h.Config != nil && h.Config.Server.Tokens.MaxLinked > 0 {
		var count int
		if h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > strftime('%s','now'))`, identity.OwnerID).Scan(&count) != nil || count >= h.Config.Server.Tokens.MaxLinked {
			http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
			return
		}
	}
	var duplicate int
	if h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND name = ?`, identity.OwnerID, name).Scan(&duplicate) != nil || duplicate > 0 {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	key, err := h.ownerTokenKey()
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	token, err := generateOwnerToken()
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	hash := sha256.Sum256([]byte(token))
	ciphertext, err := security.EncryptWithSecret(key, []byte(token), ownerTokenEncryptionInfo)
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	tokenUUID, idErr := uuid.NewV7()
	if idErr != nil {
		http.Error(w, "Unable to create token", http.StatusInternalServerError)
		return
	}
	publicID := tokenUUID.String()
	if h.DB.APITokenIDColumn() == "public_id" {
		_, err = h.DB.ExecContext(r.Context(), `INSERT INTO api_tokens(owner_id, kind, name, scope, token_hash, token_prefix, token_last4, token_enc, expires_at, public_id) VALUES(?, 'linked', ?, ?, ?, ?, ?, ?, ?, ?)`, identity.OwnerID, name, scope, hex.EncodeToString(hash[:]), ownerTokenPrefix(token), ownerTokenSuffix(token), base64.StdEncoding.EncodeToString(ciphertext), expires, publicID)
	} else {
		_, err = h.DB.ExecContext(r.Context(), `INSERT INTO api_tokens(id, owner_id, kind, name, scope, token_hash, token_prefix, token_last4, token_enc, expires_at) VALUES(?, ?, 'linked', ?, ?, ?, ?, ?, ?, ?)`, publicID, identity.OwnerID, name, scope, hex.EncodeToString(hash[:]), ownerTokenPrefix(token), ownerTokenSuffix(token), base64.StdEncoding.EncodeToString(ciphertext), expires)
	}
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	if h.TokenAuditLogger != nil {
		h.TokenAuditLogger("token.created", "web", identity.OwnerID, ownerTokenPrefix(token))
	}
	if h.setOwnerTokenFlash(w, r, ownerTokenFlash{Token: token, Action: "linked-created", ID: publicID}) != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=unavailable", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/server/preferences/tokens#token-"+publicID, http.StatusSeeOther)
}

func (h *PagesHandler) ServerPreferencesLinkedTokenActionHandler(w http.ResponseWriter, r *http.Request, publicID, action string) {
	identity, err := h.ownerFromCookie(r)
	if err != nil || identity.Kind != "primary" {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	var id string
	var name, encrypted string
	var prefix string
	if h.DB.QueryRowContext(r.Context(), `SELECT `+h.DB.APITokenIDColumn()+`, name, token_enc, token_prefix FROM api_tokens WHERE `+h.DB.APITokenIDColumn()+` = ? AND owner_id = ? AND kind = 'linked' AND revoked_at IS NULL`, publicID, identity.OwnerID).Scan(&id, &name, &encrypted, &prefix) != nil {
		http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
		return
	}
	switch action {
	case "reveal":
		token, err := h.decryptOwnerToken(encrypted)
		if err == nil {
			if h.setOwnerTokenFlash(w, r, ownerTokenFlash{Token: token, Action: "revealed", ID: publicID}) == nil {
				http.Redirect(w, r, "/server/preferences/tokens#token-"+publicID, http.StatusSeeOther)
				return
			}
			break
		}
	case "rotate":
		key, err := h.ownerTokenKey()
		if err == nil {
			var token string
			token, err = generateOwnerToken()
			if err == nil {
				hash := sha256.Sum256([]byte(token))
				var ciphertext []byte
				ciphertext, err = security.EncryptWithSecret(key, []byte(token), ownerTokenEncryptionInfo)
				if err == nil {
					_, err = h.DB.ExecContext(r.Context(), `UPDATE api_tokens SET token_hash = ?, token_prefix = ?, token_last4 = ?, token_enc = ?, rotated_at = strftime('%s','now') WHERE `+h.DB.APITokenIDColumn()+` = ? AND owner_id = ? AND revoked_at IS NULL`, hex.EncodeToString(hash[:]), ownerTokenPrefix(token), ownerTokenSuffix(token), base64.StdEncoding.EncodeToString(ciphertext), id, identity.OwnerID)
					if err == nil {
						if h.TokenAuditLogger != nil {
							h.TokenAuditLogger("token.rotated", "web", identity.OwnerID, ownerTokenPrefix(token))
						}
						if h.setOwnerTokenFlash(w, r, ownerTokenFlash{Token: token, Action: "linked-rotated", ID: publicID}) == nil {
							http.Redirect(w, r, "/server/preferences/tokens#token-"+publicID, http.StatusSeeOther)
							return
						}
					}
				}
			}
		}
	case "update":
		if r.ParseForm() == nil {
			newName := strings.TrimSpace(r.FormValue("name"))
			expires, expiryErr := tokenExpiryForm(r)
			var duplicate int
			dupErr := h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND name = ? AND `+h.DB.APITokenIDColumn()+` <> ?`, identity.OwnerID, newName, id).Scan(&duplicate)
			if nameLength := utf8.RuneCountInString(newName); nameLength > 0 && nameLength <= 64 && expiryErr == nil && dupErr == nil && duplicate == 0 {
				_, err = h.DB.ExecContext(r.Context(), `UPDATE api_tokens SET name = ?, expires_at = ? WHERE `+h.DB.APITokenIDColumn()+` = ? AND owner_id = ? AND kind = 'linked' AND revoked_at IS NULL`, newName, expires, id, identity.OwnerID)
				if err == nil {
					http.Redirect(w, r, "/server/preferences/tokens?status=updated&token_id="+publicID+"#token-"+publicID, http.StatusSeeOther)
					return
				}
			}
		}
	case "revoke":
		_, err = h.DB.ExecContext(r.Context(), `UPDATE api_tokens SET revoked_at = strftime('%s','now'), revoked_reason = 'owner' WHERE `+h.DB.APITokenIDColumn()+` = ? AND owner_id = ? AND kind = 'linked' AND revoked_at IS NULL`, id, identity.OwnerID)
		if err == nil {
			if h.TokenAuditLogger != nil {
				h.TokenAuditLogger("token.revoked", "web", identity.OwnerID, prefix)
			}
			http.Redirect(w, r, "/server/preferences/tokens?status=revoked&token_id="+publicID+"#token-"+publicID, http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/server/preferences/tokens#token-"+publicID, http.StatusSeeOther)
}

func (h *PagesHandler) ServerPreferencesTokenRevealHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cookie, err := r.Cookie(ownerTokenCookieName)
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=invalid", http.StatusSeeOther)
		return
	}
	identity, err := h.validatePrimaryToken(r.Context(), cookie.Value)
	if err != nil {
		h.clearOwnerTokenCookie(w, r)
		http.Redirect(w, r, "/server/preferences/tokens?status=invalid", http.StatusSeeOther)
		return
	}
	token, err := h.decryptOwnerToken(identity.Encrypted)
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=unavailable", http.StatusSeeOther)
		return
	}
	if h.TokenAuditLogger != nil {
		h.TokenAuditLogger("token.revealed", "web", identity.OwnerID, identity.Prefix)
	}
	if h.setOwnerTokenFlash(w, r, ownerTokenFlash{Token: token, Action: "revealed"}) != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=unavailable", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/server/preferences/tokens#primary", http.StatusSeeOther)
}

func (h *PagesHandler) ServerPreferencesTokenForgetHandler(w http.ResponseWriter, r *http.Request) {
	h.clearOwnerTokenCookie(w, r)
	w.Header().Set("Clear-Site-Data", `"storage"`)
	http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
}

func (h *PagesHandler) ServerPreferencesTokenRotateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cookie, err := r.Cookie(ownerTokenCookieName)
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=invalid", http.StatusSeeOther)
		return
	}
	identity, err := h.validatePrimaryToken(r.Context(), cookie.Value)
	if err != nil {
		h.clearOwnerTokenCookie(w, r)
		http.Redirect(w, r, "/server/preferences/tokens?status=invalid", http.StatusSeeOther)
		return
	}
	token, err := h.rotateOwnerToken(r.Context(), identity)
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=unavailable", http.StatusSeeOther)
		return
	}
	h.setOwnerTokenCookie(w, r, token)
	if h.TokenAuditLogger != nil {
		h.TokenAuditLogger("token.rotated", "web", identity.OwnerID, identity.Prefix)
	}
	if h.setOwnerTokenFlash(w, r, ownerTokenFlash{Token: token, Action: "rotated"}) != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=unavailable", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/server/preferences/tokens#primary", http.StatusSeeOther)
}

func (h *PagesHandler) ServerPreferencesTokenRevokeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cookie, err := r.Cookie(ownerTokenCookieName)
	if err != nil {
		http.Redirect(w, r, "/server/preferences/tokens?status=invalid", http.StatusSeeOther)
		return
	}
	identity, err := h.validatePrimaryToken(r.Context(), cookie.Value)
	if err != nil {
		h.clearOwnerTokenCookie(w, r)
		http.Redirect(w, r, "/server/preferences/tokens?status=invalid", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil || !constantTimeLastFour(r.FormValue("confirm"), identity.Last4) {
		http.Redirect(w, r, "/server/preferences/tokens?status=confirm-invalid", http.StatusSeeOther)
		return
	}
	tokens, resources, err := h.deleteOwner(r.Context(), identity.OwnerID)
	if err != nil {
		slog.Warn("owner token revocation failed", "owner_id", identity.OwnerID, "error", err)
		http.Redirect(w, r, "/server/preferences/tokens?status=unavailable", http.StatusSeeOther)
		return
	}
	h.clearOwnerTokenCookie(w, r)
	w.Header().Set("Clear-Site-Data", `"storage"`)
	if h.TokenOwnerRevokeLogger != nil {
		h.TokenOwnerRevokeLogger("web", identity.OwnerID, identity.Prefix, tokens, resources)
	}
	http.Redirect(w, r, "/server/preferences/tokens?status=revoked", http.StatusSeeOther)
}

func (h *PagesHandler) renderOwnerTokensPage(w http.ResponseWriter, r *http.Request, revealedToken, newToken, action string) {
	h.renderOwnerTokensPageState(w, r, revealedToken, newToken, action, "", "", "")
}

func (h *PagesHandler) renderOwnerTokensPageState(w http.ResponseWriter, r *http.Request, revealedToken, newToken, action, revealTokenID, newTokenID, actionTokenID string) {
	data := OwnerTokensPageData{
		PageData: h.NewPageData(r), RestoreError: r.URL.Query().Get("status") == "invalid", RevokeInvalid: r.URL.Query().Get("status") == "confirm-invalid",
		RevealToken: revealedToken, NewToken: newToken, TokenAction: action,
		RevealTokenID: revealTokenID, NewTokenID: newTokenID, ActionTokenID: actionTokenID,
	}
	if data.TokenAction == "" {
		data.TokenAction = r.URL.Query().Get("status")
	}
	if data.ActionTokenID == "" {
		data.ActionTokenID = r.URL.Query().Get("token_id")
	}
	if newToken != "" {
		if identity, err := h.validatePrimaryToken(r.Context(), newToken); err == nil {
			data.HasOwner = true
			data.PrimaryMasked = maskOwnerTokenSuffix(identity.Last4)
			data.LinkedTokens = h.ownerLinkedTokens(r.Context(), identity.OwnerID)
			data.RevokeLast4 = identity.Last4
			data.RevokeTokens, data.RevokeResources, data.RevokeCountsAvailable = h.ownerTokenCounts(r.Context(), identity.OwnerID)
		}
	}
	if cookie, err := r.Cookie(ownerTokenCookieName); err == nil && !data.HasOwner {
		identity, validationErr := h.validatePrimaryToken(r.Context(), cookie.Value)
		if validationErr == nil {
			data.HasOwner = true
			h.setOwnerTokenCookie(w, r, cookie.Value)
			if revealedToken == "" || revealTokenID != "" {
				data.PrimaryMasked = maskOwnerTokenSuffix(identity.Last4)
			}
			data.LinkedTokens = h.ownerLinkedTokens(r.Context(), identity.OwnerID)
			data.RevokeLast4 = identity.Last4
			data.RevokeTokens, data.RevokeResources, data.RevokeCountsAvailable = h.ownerTokenCounts(r.Context(), identity.OwnerID)
		} else {
			h.clearOwnerTokenCookie(w, r)
		}
	}
	h.renderNegotiated(w, r, "preferences_tokens.tmpl", data, data)
}

func (h *PagesHandler) ownerTokenCounts(ctx context.Context, ownerID string) (int64, int64, bool) {
	if h.DB == nil {
		return 0, 0, false
	}
	var tokens int64
	if err := h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ?`, ownerID).Scan(&tokens); err != nil {
		return 0, 0, false
	}
	return tokens, 0, true
}

func constantTimeLastFour(confirmation, lastFour string) bool {
	return len(confirmation) == len(lastFour) && subtle.ConstantTimeCompare([]byte(confirmation), []byte(lastFour)) == 1
}

func (h *PagesHandler) deleteOwner(ctx context.Context, ownerID string) (tokens, resources int64, err error) {
	if h.DB == nil {
		return 0, 0, errors.New("owner database is unavailable")
	}
	err = h.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ?`, ownerID).Scan(&tokens); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM owners WHERE id = ? AND id <> 'system'`, ownerID)
		if err != nil {
			return err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if deleted != 1 {
			return sql.ErrNoRows
		}
		return nil
	})
	return tokens, 0, err
}

func (h *PagesHandler) ownerLinkedTokens(ctx context.Context, ownerID string) []OwnerLinkedTokenView {
	if h.DB == nil {
		return nil
	}
	rows, err := h.DB.QueryContext(ctx, `SELECT `+h.DB.APITokenIDColumn()+`, name, scope, token_last4, created_at, last_used_at, expires_at, revoked_at
		FROM api_tokens WHERE owner_id = ? AND kind = 'linked' ORDER BY created_at, `+h.DB.APITokenIDColumn()+``, ownerID)
	if err != nil {
		return nil
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			slog.Warn("owner linked token rows close failed", "error", closeErr)
		}
	}()
	var tokens []OwnerLinkedTokenView
	for rows.Next() {
		var token OwnerLinkedTokenView
		var last4 string
		var created int64
		var lastUsed, expires, revoked sql.NullInt64
		if rows.Scan(&token.ID, &token.Name, &token.Scope, &last4, &created, &lastUsed, &expires, &revoked) != nil {
			return nil
		}
		token.Masked = maskOwnerTokenSuffix(last4)
		token.Created = formatOwnerTokenTime(created)
		token.LastUsed = formatOwnerTokenNullableTime(lastUsed)
		token.Expires = formatOwnerTokenNullableTime(expires)
		token.Status = "active"
		token.Expiry = "never"
		if expires.Valid {
			token.Expiry = "custom"
			token.ExpiresOn = time.Unix(expires.Int64, 0).UTC().Format("2006-01-02")
		}
		if revoked.Valid {
			token.Status = "revoked"
		} else if expires.Valid && expires.Int64 <= time.Now().Unix() {
			token.Status = "expired"
		}
		tokens = append(tokens, token)
	}
	return tokens
}

func (h *PagesHandler) decryptOwnerToken(encrypted string) (string, error) {
	key, err := h.ownerTokenKey()
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	plaintext, err := security.DecryptWithSecret(key, ciphertext, ownerTokenEncryptionInfo)
	return string(plaintext), err
}

func ownerTokenSuffix(token string) string {
	if len(token) < 4 {
		return ""
	}
	return token[len(token)-4:]
}

func maskOwnerTokenSuffix(suffix string) string {
	return "own_••••••••••••••••••••••••" + suffix
}

func formatOwnerTokenTime(unix int64) string {
	return time.Unix(unix, 0).UTC().Format("2006-01-02")
}

func formatOwnerTokenNullableTime(value sql.NullInt64) string {
	if !value.Valid {
		return "Never"
	}
	return formatOwnerTokenTime(value.Int64)
}

func (h *PagesHandler) rotateOwnerToken(ctx context.Context, identity OwnerTokenIdentity) (string, error) {
	key, err := h.ownerTokenKey()
	if err != nil {
		return "", err
	}
	token, err := generateOwnerToken()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(token))
	ciphertext, err := security.EncryptWithSecret(key, []byte(token), ownerTokenEncryptionInfo)
	if err != nil {
		return "", err
	}
	_, err = h.DB.ExecContext(ctx, `UPDATE api_tokens SET token_hash = ?, token_prefix = ?, token_last4 = ?, token_enc = ?, rotated_at = strftime('%s', 'now') WHERE `+h.DB.APITokenIDColumn()+` = ? AND kind = 'primary' AND revoked_at IS NULL`, hex.EncodeToString(hash[:]), ownerTokenPrefix(token), ownerTokenSuffix(token), base64.StdEncoding.EncodeToString(ciphertext), identity.TokenID)
	return token, err
}

func (h *PagesHandler) setOwnerTokenCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: ownerTokenCookieName, Value: token, Path: "/", MaxAge: ownerTokenCookieMaxAge(h.Config), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (h *PagesHandler) clearOwnerTokenCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: ownerTokenCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (h *PagesHandler) issueOwnerTokenAPI(w http.ResponseWriter, r *http.Request) {
	if token, ok := bearerTokenFromHeader(r); ok {
		valid := false
		if h.ValidateBearerToken != nil {
			valid = h.ValidateBearerToken(token)
		} else {
			_, err := h.validateOwnerBearer(r.Context(), token)
			valid = err == nil
		}
		if valid {
			SendAPIResponseError(w, http.StatusConflict, "CONFLICT", "An owner token is already active for this caller", nil)
			return
		}
	}
	identity, token, err := h.createPrimaryToken(r.Context())
	if err != nil {
		slog.Warn("owner token issuance failed", "error", err)
		SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to issue an owner token", nil)
		return
	}
	if h.TokenAuditLogger != nil {
		h.TokenAuditLogger("token.created", "issue", identity.OwnerID, identity.Prefix)
	}
	w.Header().Set("Location", "/api/v1/server/preferences/tokens")
	SendAPIResponseCreated(w, map[string]string{"owner_token": token})
}

func (h *PagesHandler) APIV1ServerTokensIssueHandler(w http.ResponseWriter, r *http.Request) {
	h.issueOwnerTokenAPI(w, r)
}

func (h *PagesHandler) validateOwnerBearer(ctx context.Context, token string) (OwnerTokenIdentity, error) {
	if h.DB == nil || !validOwnerPrimaryToken(token) {
		return OwnerTokenIdentity{}, sql.ErrNoRows
	}
	hash := sha256.Sum256([]byte(token))
	identity, err := h.findOwnerToken(ctx, token, "1 = 1")
	if err != nil {
		return OwnerTokenIdentity{}, err
	}
	identity.TokenHash = hex.EncodeToString(hash[:])
	h.DB.MarkOwnerUsage(identity.TokenID, identity.OwnerID, time.Now())
	return identity, nil
}

func (h *PagesHandler) APIV1ServerTokensListHandler(w http.ResponseWriter, r *http.Request) {
	identity, err := h.validatePrimaryBearer(r)
	if err != nil {
		writePrimaryBearerAuthError(w, err)
		return
	}
	rows, err := h.DB.QueryContext(r.Context(), `SELECT `+h.DB.APITokenIDColumn()+`, kind, name, scope, token_prefix, token_last4, created_at, last_used_at, expires_at, revoked_at
		FROM api_tokens WHERE owner_id = ? ORDER BY kind, created_at, `+h.DB.APITokenIDColumn()+``, identity.OwnerID)
	if err != nil {
		SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to list owner tokens", nil)
		return
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			slog.Warn("owner token rows close failed", "error", closeErr)
		}
	}()
	primary := map[string]any(nil)
	linked := make([]map[string]any, 0)
	for rows.Next() {
		var id string
		var kind string
		var name sql.NullString
		var scope string
		var prefix, last4 string
		var created int64
		var lastUsedInt, expiresInt, revokedInt sql.NullInt64
		if err := rows.Scan(&id, &kind, &name, &scope, &prefix, &last4, &created, &lastUsedInt, &expiresInt, &revokedInt); err != nil {
			SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to list owner tokens", nil)
			return
		}
		status := "active"
		if revokedInt.Valid {
			status = "revoked"
		} else if expiresInt.Valid && expiresInt.Int64 <= time.Now().Unix() {
			status = "expired"
		}
		masked := maskOwnerTokenSuffix(last4)
		token := map[string]any{"id": id, "kind": kind, "name": name.String, "scope": scope, "token_masked": masked, "status": status,
			"created_at": time.Unix(created, 0).UTC().Format(time.RFC3339), "last_used_at": nullableTimestamp(lastUsedInt), "expires_at": nullableTimestamp(expiresInt)}
		if kind == "primary" {
			primary = token
		} else {
			linked = append(linked, token)
		}
	}
	if err := rows.Err(); err != nil {
		SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to list owner tokens", nil)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	maxLinked := 25
	if h.Config != nil && h.Config.Server.Tokens.MaxLinked > 0 {
		maxLinked = h.Config.Server.Tokens.MaxLinked
	}
	SendAPIResponseOK(w, map[string]any{"primary": primary, "linked": linked, "max_linked": maxLinked}, nil)
}

func nullableTimestamp(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return time.Unix(value.Int64, 0).UTC().Format(time.RFC3339)
}

func timestampValue(value any) any {
	if value == nil {
		return nil
	}
	if timestamp, ok := value.(int64); ok {
		return time.Unix(timestamp, 0).UTC().Format(time.RFC3339)
	}
	return nil
}

func (h *PagesHandler) APIV1ServerPrimaryTokenActionHandler(w http.ResponseWriter, r *http.Request, action string) {
	identity, err := h.validatePrimaryBearer(r)
	if err != nil {
		writePrimaryBearerAuthError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if action == "reveal" {
		token, err := h.decryptOwnerToken(identity.Encrypted)
		if err != nil {
			SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to reveal token", nil)
			return
		}
		if h.TokenAuditLogger != nil {
			h.TokenAuditLogger("token.revealed", "api", identity.OwnerID, identity.Prefix)
		}
		SendAPIResponseOK(w, map[string]string{"owner_token": token}, nil)
		return
	}
	if action == "rotate" {
		token, err := h.rotateOwnerToken(r.Context(), identity)
		if err != nil {
			SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to rotate token", nil)
			return
		}
		if h.TokenAuditLogger != nil {
			h.TokenAuditLogger("token.rotated", "api", identity.OwnerID, identity.Prefix)
		}
		SendAPIResponseOK(w, map[string]string{"owner_token": token}, nil)
		return
	}
	SendAPIResponseError(w, http.StatusNotFound, "NOT_FOUND", "Token action not found", nil)
}

func (h *PagesHandler) APIV1ServerPrimaryTokenRevokeHandler(w http.ResponseWriter, r *http.Request) {
	identity, err := h.validatePrimaryBearer(r)
	if err != nil {
		writePrimaryBearerAuthError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED", "A JSON confirmation is required", nil)
		return
	}
	var input struct {
		Confirm string `json:"confirm"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED", "The confirmation is invalid", nil)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || !constantTimeLastFour(input.Confirm, identity.Last4) {
		SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED", "The confirmation is invalid", nil)
		return
	}
	tokens, resources, err := h.deleteOwner(r.Context(), identity.OwnerID)
	if err != nil {
		slog.Warn("owner token revocation failed", "owner_id", identity.OwnerID, "error", err)
		SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to revoke owner token", nil)
		return
	}
	if h.TokenOwnerRevokeLogger != nil {
		h.TokenOwnerRevokeLogger("api", identity.OwnerID, identity.Prefix, tokens, resources)
	}
	SendAPIResponseOK(w, map[string]int64{"tokens": tokens, "resources": resources}, nil)
}

func (h *PagesHandler) APIV1ServerLinkedTokenCreateHandler(w http.ResponseWriter, r *http.Request) {
	identity, err := h.validatePrimaryBearer(r)
	if err != nil {
		writePrimaryBearerAuthError(w, err)
		return
	}
	var input struct {
		Name      string `json:"name"`
		Scope     string `json:"scope"`
		Expires   string `json:"expires"`
		ExpiresOn string `json:"expires_on"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil {
		SendAPIResponseError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid token request", nil)
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if nameLength := utf8.RuneCountInString(input.Name); nameLength < 1 || nameLength > 64 {
		SendAPIResponseError(w, http.StatusBadRequest, "BAD_REQUEST", "Name must contain 1 to 64 characters", nil)
		return
	}
	if input.Scope == "" {
		input.Scope = OwnerTokenScopeReadWrite
	}
	if !validLinkedTokenScope(input.Scope) {
		SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED", "Scope must be read or read-write", nil)
		return
	}
	expires, err := tokenExpiryAPI(input.Expires, input.ExpiresOn)
	if err != nil {
		SendAPIResponseError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid expiry", nil)
		return
	}
	var count int
	if err := h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > strftime('%s','now'))`, identity.OwnerID).Scan(&count); err != nil {
		SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to count tokens", nil)
		return
	}
	if h.Config != nil && h.Config.Server.Tokens.MaxLinked > 0 && count >= h.Config.Server.Tokens.MaxLinked {
		SendAPIResponseError(w, http.StatusConflict, "CONFLICT", "Linked token limit reached", nil)
		return
	}
	var duplicate int
	if h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND name = ?`, identity.OwnerID, input.Name).Scan(&duplicate) != nil || duplicate > 0 {
		SendAPIResponseError(w, http.StatusConflict, "CONFLICT", "Token name already exists", nil)
		return
	}
	key, err := h.ownerTokenKey()
	if err != nil {
		SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Token encryption unavailable", nil)
		return
	}
	token, err := generateOwnerToken()
	if err != nil {
		SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to create token", nil)
		return
	}
	hash := sha256.Sum256([]byte(token))
	ciphertext, err := security.EncryptWithSecret(key, []byte(token), ownerTokenEncryptionInfo)
	if err != nil {
		SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to create token", nil)
		return
	}
	tokenUUID, idErr := uuid.NewV7()
	if idErr != nil {
		http.Error(w, "Unable to create token", http.StatusInternalServerError)
		return
	}
	publicID := tokenUUID.String()
	if h.DB.APITokenIDColumn() == "public_id" {
		_, err = h.DB.ExecContext(r.Context(), `INSERT INTO api_tokens(owner_id, kind, name, scope, token_hash, token_prefix, token_last4, token_enc, expires_at, public_id) VALUES(?, 'linked', ?, ?, ?, ?, ?, ?, ?, ?)`, identity.OwnerID, input.Name, input.Scope, hex.EncodeToString(hash[:]), ownerTokenPrefix(token), ownerTokenSuffix(token), base64.StdEncoding.EncodeToString(ciphertext), expires, publicID)
	} else {
		_, err = h.DB.ExecContext(r.Context(), `INSERT INTO api_tokens(id, owner_id, kind, name, scope, token_hash, token_prefix, token_last4, token_enc, expires_at) VALUES(?, ?, 'linked', ?, ?, ?, ?, ?, ?, ?)`, publicID, identity.OwnerID, input.Name, input.Scope, hex.EncodeToString(hash[:]), ownerTokenPrefix(token), ownerTokenSuffix(token), base64.StdEncoding.EncodeToString(ciphertext), expires)
	}
	if err != nil {
		SendAPIResponseError(w, http.StatusConflict, "CONFLICT", "Token name already exists", nil)
		return
	}
	if h.TokenAuditLogger != nil {
		h.TokenAuditLogger("token.created", "api", identity.OwnerID, ownerTokenPrefix(token))
	}
	w.Header().Set("Cache-Control", "no-store")
	SendAPIResponseCreated(w, map[string]any{"id": publicID, "name": input.Name, "scope": input.Scope, "linked_token": token, "expires_at": timestampValue(expires)})
}

func (h *PagesHandler) APIV1ServerLinkedTokenActionHandler(w http.ResponseWriter, r *http.Request, publicID, action string) {
	identity, err := h.validatePrimaryBearer(r)
	if err != nil {
		writePrimaryBearerAuthError(w, err)
		return
	}
	var id string
	var name, encrypted, prefix string
	if h.DB.QueryRowContext(r.Context(), `SELECT `+h.DB.APITokenIDColumn()+`, name, token_enc, token_prefix FROM api_tokens WHERE `+h.DB.APITokenIDColumn()+` = ? AND owner_id = ? AND kind = 'linked'`, publicID, identity.OwnerID).Scan(&id, &name, &encrypted, &prefix) != nil {
		SendAPIResponseError(w, http.StatusNotFound, "NOT_FOUND", "Token not found", nil)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch action {
	case "reveal":
		var token string
		token, err = h.decryptOwnerToken(encrypted)
		if err == nil {
			if h.TokenAuditLogger != nil {
				h.TokenAuditLogger("token.revealed", "api", identity.OwnerID, prefix)
			}
			SendAPIResponseOK(w, map[string]string{"linked_token": token}, nil)
			return
		}
	case "rotate":
		var token string
		token, err = generateOwnerToken()
		if err == nil {
			key, keyErr := h.ownerTokenKey()
			if keyErr != nil {
				err = keyErr
			} else {
				hash := sha256.Sum256([]byte(token))
				var cipher []byte
				cipher, err = security.EncryptWithSecret(key, []byte(token), ownerTokenEncryptionInfo)
				if err == nil {
					_, err = h.DB.ExecContext(r.Context(), `UPDATE api_tokens SET token_hash = ?, token_prefix = ?, token_last4 = ?, token_enc = ?, rotated_at = strftime('%s','now') WHERE `+h.DB.APITokenIDColumn()+` = ? AND owner_id = ? AND revoked_at IS NULL`, hex.EncodeToString(hash[:]), ownerTokenPrefix(token), ownerTokenSuffix(token), base64.StdEncoding.EncodeToString(cipher), id, identity.OwnerID)
				}
			}
		}
		if err == nil {
			if h.TokenAuditLogger != nil {
				h.TokenAuditLogger("token.rotated", "api", identity.OwnerID, ownerTokenPrefix(token))
			}
			SendAPIResponseOK(w, map[string]string{"linked_token": token}, nil)
			return
		}
	case "update":
		var input struct {
			Name      string `json:"name"`
			Expires   string `json:"expires"`
			ExpiresOn string `json:"expires_on"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) == nil {
			input.Name = strings.TrimSpace(input.Name)
			var expires any
			expires, err = tokenExpiryAPI(input.Expires, input.ExpiresOn)
			var duplicate int
			dupErr := h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND name = ? AND `+h.DB.APITokenIDColumn()+` <> ?`, identity.OwnerID, input.Name, id).Scan(&duplicate)
			if nameLength := utf8.RuneCountInString(input.Name); err == nil && dupErr == nil && duplicate == 0 && nameLength > 0 && nameLength <= 64 {
				_, err = h.DB.ExecContext(r.Context(), `UPDATE api_tokens SET name = ?, expires_at = ? WHERE `+h.DB.APITokenIDColumn()+` = ? AND owner_id = ? AND kind = 'linked' AND revoked_at IS NULL`, input.Name, expires, id, identity.OwnerID)
				if err == nil {
					SendAPIResponseOK(w, map[string]any{"id": publicID, "name": input.Name, "expires_at": expires}, nil)
					return
				}
			}
		}
	case "revoke":
		_, err = h.DB.ExecContext(r.Context(), `UPDATE api_tokens SET revoked_at = strftime('%s','now'), revoked_reason = 'owner' WHERE `+h.DB.APITokenIDColumn()+` = ? AND owner_id = ? AND kind = 'linked' AND revoked_at IS NULL`, id, identity.OwnerID)
		if err == nil {
			if h.TokenAuditLogger != nil {
				h.TokenAuditLogger("token.revoked", "api", identity.OwnerID, prefix)
			}
			SendAPIResponseOK(w, map[string]string{"id": publicID}, nil)
			return
		}
	}
	SendAPIResponseError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to complete token action", nil)
}
