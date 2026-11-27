package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/db"
)

func TestLinkedTokenRevealRendersOnlyItsLinkedCard(t *testing.T) {
	database, err := db.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	_, err = database.Exec(`CREATE TABLE owners (id TEXT PRIMARY KEY, last_seen_at INTEGER);
		CREATE TABLE api_tokens (
			id TEXT PRIMARY KEY,
			owner_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT 'read-write',
			name TEXT,
			token_hash TEXT NOT NULL,
			token_prefix TEXT NOT NULL,
			token_last4 TEXT NOT NULL,
			token_enc TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT 0,
			last_used_at INTEGER,
			expires_at INTEGER,
			revoked_at INTEGER
		);`)
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestPagesHandler()
	handler.DB = database
	handler.Config = config.DefaultConfig()
	handler.Config.Server.Security.EncryptionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	primary, primaryToken, err := handler.createPrimaryToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const linkedToken = "own_0123456789ABCDEFGHIJKLMNOPQRSTUV"
	linkedID := uuid.Must(uuid.NewV7())
	_, err = database.Exec(`INSERT INTO api_tokens(id, owner_id, kind, name, scope, token_hash, token_prefix, token_last4, token_enc)
		VALUES(?, ?, 'linked', 'automation', 'read', 'linked-hash', 'own_01234567', 'RSTV', 'encrypted')`, linkedID, primary.OwnerID)
	if err != nil {
		t.Fatal(err)
	}

	var rendered OwnerTokensPageData
	handler.Render = func(_ http.ResponseWriter, _ *http.Request, _ string, data interface{}) error {
		rendered = data.(OwnerTokensPageData)
		return nil
	}
	request := httptest.NewRequest("GET", "/server/preferences/tokens", nil)
	request.AddCookie(&http.Cookie{Name: OwnerTokenCookieName, Value: primaryToken})
	response := httptest.NewRecorder()
	handler.renderOwnerTokensPageState(response, request, linkedToken, "", "revealed", linkedID.String(), "", "")

	if rendered.RevealToken != linkedToken || rendered.RevealTokenID != linkedID.String() {
		t.Fatalf("linked reveal state = token %q, id %s; want linked card %s", rendered.RevealToken, rendered.RevealTokenID, linkedID)
	}
	if rendered.PrimaryMasked != maskOwnerTokenSuffix(primary.Last4) {
		t.Fatalf("primary token = %q; want masked primary %q", rendered.PrimaryMasked, maskOwnerTokenSuffix(primary.Last4))
	}
	if len(rendered.LinkedTokens) != 1 || rendered.LinkedTokens[0].Status != "active" || rendered.LinkedTokens[0].Scope != OwnerTokenScopeRead {
		t.Fatalf("linked token list = %#v; want one active token", rendered.LinkedTokens)
	}
	if _, err := uuid.Parse(rendered.LinkedTokens[0].ID); err != nil {
		t.Fatalf("linked token public ID is not a UUID: %q", rendered.LinkedTokens[0].ID)
	}
}

func TestOwnerTokenFlashIsConsumedAfterRedirect(t *testing.T) {
	handler := newTestPagesHandler()
	handler.Config = config.DefaultConfig()
	handler.Config.Server.Security.EncryptionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	const token = "own_0123456789ABCDEFGHIJKLMNOPQRSTUV"
	post := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/server/preferences/token/reveal", nil)
	if err := handler.setOwnerTokenFlash(post, request, ownerTokenFlash{Token: token, Action: "revealed"}); err != nil {
		t.Fatal(err)
	}
	http.Redirect(post, request, "/server/preferences/tokens#primary", http.StatusSeeOther)
	if post.Code != http.StatusSeeOther {
		t.Fatalf("POST status = %d, want %d", post.Code, http.StatusSeeOther)
	}
	if bytes.Contains(post.Body.Bytes(), []byte(token)) {
		t.Fatal("POST response contains the raw token")
	}
	var rendered OwnerTokensPageData
	handler.Render = func(_ http.ResponseWriter, _ *http.Request, _ string, data interface{}) error {
		rendered = data.(OwnerTokensPageData)
		return nil
	}
	get := httptest.NewRequest(http.MethodGet, "/server/preferences/tokens", nil)
	get.AddCookie(post.Result().Cookies()[0])
	response := httptest.NewRecorder()
	handler.ServerPreferencesTokensHandler(response, get)
	if rendered.RevealToken != token || rendered.TokenAction != "revealed" {
		t.Fatalf("redirected page reveal = %q (%q), want one-time token", rendered.RevealToken, rendered.TokenAction)
	}
	if len(response.Result().Cookies()) == 0 || response.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatal("flash cookie was not cleared after the redirected page load")
	}
}

func TestPrimaryTokenBearerDistinguishesLinkedFromInvalidTokens(t *testing.T) {
	database, err := db.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	_, err = database.Exec(`CREATE TABLE owners (id TEXT PRIMARY KEY, last_seen_at INTEGER);
		CREATE TABLE api_tokens (
			id TEXT PRIMARY KEY,
			owner_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT 'read-write',
			name TEXT,
			token_hash TEXT NOT NULL,
			token_prefix TEXT NOT NULL,
			token_last4 TEXT NOT NULL,
			token_enc TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT 0,
			last_used_at INTEGER,
			expires_at INTEGER,
			revoked_at INTEGER
		);`)
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestPagesHandler()
	handler.DB = database
	handler.Config = config.DefaultConfig()
	handler.Config.Server.Security.EncryptionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	primary, primaryToken, err := handler.createPrimaryToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const linkedToken = "own_0123456789ABCDEFGHIJKLMNOPQRSTUV"
	linkedHash := sha256.Sum256([]byte(linkedToken))
	_, err = database.Exec(`INSERT INTO api_tokens(id, owner_id, kind, name, scope, token_hash, token_prefix, token_last4, token_enc)
		VALUES(?, ?, 'linked', 'automation', 'read', ?, ?, ?, 'encrypted')`, uuid.Must(uuid.NewV7()), primary.OwnerID,
		hex.EncodeToString(linkedHash[:]), ownerTokenPrefix(linkedToken), ownerTokenSuffix(linkedToken))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		token      string
		wantStatus int
		wantErr    error
	}{
		{name: "primary", token: primaryToken, wantStatus: http.StatusOK},
		{name: "linked", token: linkedToken, wantStatus: http.StatusForbidden, wantErr: errInsufficientTokenScope},
		{name: "missing", wantStatus: http.StatusUnauthorized, wantErr: sql.ErrNoRows},
		{name: "invalid", token: "own_00000000000000000000000000000000", wantStatus: http.StatusUnauthorized, wantErr: sql.ErrNoRows},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/tokens", nil)
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			response := httptest.NewRecorder()
			handler.APIV1ServerTokensListHandler(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.name == "linked" && response.Header().Get("WWW-Authenticate") != `Bearer error="insufficient_scope"` {
				t.Fatalf("linked token challenge = %q, want insufficient_scope", response.Header().Get("WWW-Authenticate"))
			}
			if test.name == "primary" {
				var envelope struct {
					Data struct {
						Primary   map[string]any   `json:"primary"`
						Linked    []map[string]any `json:"linked"`
						MaxLinked float64          `json:"max_linked"`
					} `json:"data"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
					t.Fatalf("decode token list response: %v", err)
				}
				if envelope.Data.Primary["kind"] != "primary" || envelope.Data.Primary["scope"] != OwnerTokenScopeGlobal || len(envelope.Data.Linked) != 1 || envelope.Data.MaxLinked != 25 {
					t.Fatalf("token list data = %#v, want primary, one linked token, and max_linked 25", envelope.Data)
				}
				if _, ok := envelope.Data.Linked[0]["token_masked"]; !ok {
					t.Fatalf("linked token object lacks token_masked: %#v", envelope.Data.Linked[0])
				}
				if envelope.Data.Linked[0]["scope"] != OwnerTokenScopeRead {
					t.Fatalf("linked token scope = %#v, want read", envelope.Data.Linked[0]["scope"])
				}
			}
			if test.wantErr != nil && !errors.Is(func() error {
				_, err := handler.validatePrimaryBearer(request)
				return err
			}(), test.wantErr) {
				t.Fatalf("primary token validation error does not match %v", test.wantErr)
			}
		})
	}
}

func TestPrimaryTokenRevokeRequiresConfirmationAndDeletesOwner(t *testing.T) {
	database, err := db.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	_, err = database.Exec(`CREATE TABLE owners (id TEXT PRIMARY KEY, last_seen_at INTEGER);
		CREATE TABLE api_tokens (
			id TEXT PRIMARY KEY,
			owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
			kind TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT 'read-write',
			name TEXT,
			token_hash TEXT NOT NULL,
			token_prefix TEXT NOT NULL,
			token_last4 TEXT NOT NULL,
			token_enc TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT 0,
			last_used_at INTEGER,
			expires_at INTEGER,
			revoked_at INTEGER
		);`)
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestPagesHandler()
	handler.DB = database
	handler.Config = config.DefaultConfig()
	handler.Config.Server.Security.EncryptionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	type revokeAudit struct {
		source, ownerID, prefix string
		tokens, resources       int64
	}
	var audits []revokeAudit
	handler.TokenOwnerRevokeLogger = func(source, ownerID, prefix string, tokens, resources int64) {
		audits = append(audits, revokeAudit{source: source, ownerID: ownerID, prefix: prefix, tokens: tokens, resources: resources})
	}
	identity, primaryToken, err := handler.createPrimaryToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const linkedToken = "own_0123456789ABCDEFGHIJKLMNOPQRSTUV"
	linkedHash := sha256.Sum256([]byte(linkedToken))
	_, err = database.Exec(`INSERT INTO api_tokens(id, owner_id, kind, name, scope, token_hash, token_prefix, token_last4, token_enc)
		VALUES(?, ?, 'linked', 'automation', 'read-write', ?, ?, ?, 'encrypted')`, uuid.Must(uuid.NewV7()), identity.OwnerID,
		hex.EncodeToString(linkedHash[:]), ownerTokenPrefix(linkedToken), ownerTokenSuffix(linkedToken))
	if err != nil {
		t.Fatal(err)
	}

	revoke := func(token, confirmation string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{"confirm": confirmation})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodDelete, "/api/v1/server/preferences/tokens/primary", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.APIV1ServerPrimaryTokenRevokeHandler(response, request)
		return response
	}

	invalid := revoke(primaryToken, "xxxx")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid confirmation status = %d, want %d: %s", invalid.Code, http.StatusBadRequest, invalid.Body.String())
	}
	var owners, tokens int
	if err := database.QueryRow(`SELECT COUNT(*) FROM owners WHERE id = ?`, identity.OwnerID).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE owner_id = ?`, identity.OwnerID).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if owners != 1 || tokens != 2 {
		t.Fatalf("invalid confirmation changed data: owners=%d tokens=%d, want 1 and 2", owners, tokens)
	}
	if len(audits) != 0 {
		t.Fatalf("invalid confirmation wrote revoke audit events: %#v", audits)
	}

	linked := revoke(linkedToken, identity.Last4)
	if linked.Code != http.StatusForbidden {
		t.Fatalf("linked token revoke status = %d, want %d: %s", linked.Code, http.StatusForbidden, linked.Body.String())
	}
	if len(audits) != 0 {
		t.Fatalf("linked-token attempt wrote revoke audit events: %#v", audits)
	}

	valid := revoke(primaryToken, identity.Last4)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid revoke status = %d, want %d: %s", valid.Code, http.StatusOK, valid.Body.String())
	}
	var response struct {
		Data map[string]int64 `json:"data"`
	}
	if err := json.Unmarshal(valid.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}
	if response.Data["tokens"] != 2 || response.Data["resources"] != 0 {
		t.Fatalf("revoke counts = %#v, want 2 tokens and 0 resources", response.Data)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM owners WHERE id = ?`, identity.OwnerID).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE owner_id = ?`, identity.OwnerID).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if owners != 0 || tokens != 0 {
		t.Fatalf("successful revoke left data: owners=%d tokens=%d", owners, tokens)
	}
	if len(audits) != 1 || audits[0] != (revokeAudit{source: "api", ownerID: identity.OwnerID, prefix: identity.Prefix, tokens: 2, resources: 0}) {
		t.Fatalf("revoke audit events = %#v, want one owner-scoped API event with deletion counts", audits)
	}
}
