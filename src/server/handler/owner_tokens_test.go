package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

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
	result, err := database.Exec(`INSERT INTO api_tokens(owner_id, kind, name, token_hash, token_prefix, token_last4, token_enc)
		VALUES(?, 'linked', 'automation', 'linked-hash', 'own_01234567', 'RSTV', 'encrypted')`, primary.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	linkedID, err := result.LastInsertId()
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
	handler.renderOwnerTokensPageState(response, request, linkedToken, "", "revealed", linkedID, 0, 0)

	if rendered.RevealToken != linkedToken || rendered.RevealTokenID != linkedID {
		t.Fatalf("linked reveal state = token %q, id %d; want linked card %d", rendered.RevealToken, rendered.RevealTokenID, linkedID)
	}
	if rendered.PrimaryMasked != maskOwnerTokenSuffix(primary.Last4) {
		t.Fatalf("primary token = %q; want masked primary %q", rendered.PrimaryMasked, maskOwnerTokenSuffix(primary.Last4))
	}
	if len(rendered.LinkedTokens) != 1 || rendered.LinkedTokens[0].Status != "active" {
		t.Fatalf("linked token list = %#v; want one active token", rendered.LinkedTokens)
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
