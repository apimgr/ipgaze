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
	_ "modernc.org/sqlite"
)

func TestLinkedTokenRevealRendersOnlyItsLinkedCard(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	database.SetMaxOpenConns(1)
	_, err = database.Exec(`CREATE TABLE owners (id TEXT PRIMARY KEY, last_seen_at INTEGER);
		CREATE TABLE api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			public_id TEXT UNIQUE,
			owner_id TEXT NOT NULL,
			kind TEXT NOT NULL,
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
	linkedID := uuid.NewString()
	_, err = database.Exec(`INSERT INTO api_tokens(public_id, owner_id, kind, name, token_hash, token_prefix, token_last4, token_enc)
		VALUES(?, ?, 'linked', 'automation', 'linked-hash', 'own_01234567', 'RSTV', 'encrypted')`, linkedID, primary.OwnerID)
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
	handler.renderOwnerTokensPageState(response, request, linkedToken, "", "revealed", linkedID, "", "")

	if rendered.RevealToken != linkedToken || rendered.RevealTokenID != linkedID {
		t.Fatalf("linked reveal state = token %q, id %s; want linked card %s", rendered.RevealToken, rendered.RevealTokenID, linkedID)
	}
	if rendered.PrimaryMasked != maskOwnerTokenSuffix(primary.Last4) {
		t.Fatalf("primary token = %q; want masked primary %q", rendered.PrimaryMasked, maskOwnerTokenSuffix(primary.Last4))
	}
	if len(rendered.LinkedTokens) != 1 || rendered.LinkedTokens[0].Status != "active" {
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
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	database.SetMaxOpenConns(1)
	_, err = database.Exec(`CREATE TABLE owners (id TEXT PRIMARY KEY, last_seen_at INTEGER);
		CREATE TABLE api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			public_id TEXT UNIQUE,
			owner_id TEXT NOT NULL,
			kind TEXT NOT NULL,
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
	_, err = database.Exec(`INSERT INTO api_tokens(public_id, owner_id, kind, name, token_hash, token_prefix, token_last4, token_enc)
		VALUES(?, ?, 'linked', 'automation', ?, ?, ?, 'encrypted')`, uuid.NewString(), primary.OwnerID,
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
		{name: "linked", token: linkedToken, wantStatus: http.StatusForbidden, wantErr: errPrimaryOwnerTokenRequired},
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
				if envelope.Data.Primary["kind"] != "primary" || len(envelope.Data.Linked) != 1 || envelope.Data.MaxLinked != 25 {
					t.Fatalf("token list data = %#v, want primary, one linked token, and max_linked 25", envelope.Data)
				}
				if _, ok := envelope.Data.Linked[0]["token_masked"]; !ok {
					t.Fatalf("linked token object lacks token_masked: %#v", envelope.Data.Linked[0])
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
