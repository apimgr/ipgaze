package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// NewAPIClient — URL normalisation
// ---------------------------------------------------------------------------

func TestNewAPIClient_AddsHTTPS(t *testing.T) {
	c := NewAPIClient("example.com", "tok", "ua/1", "")
	if !strings.HasPrefix(c.baseURL, "https://") {
		t.Errorf("baseURL = %q, want https:// prefix", c.baseURL)
	}
}

func TestNewAPIClient_PreservesHTTP(t *testing.T) {
	c := NewAPIClient("http://example.com", "tok", "ua/1", "")
	if !strings.HasPrefix(c.baseURL, "http://") {
		t.Errorf("baseURL = %q, want http:// prefix", c.baseURL)
	}
}

func TestNewAPIClient_PreservesHTTPS(t *testing.T) {
	c := NewAPIClient("https://example.com", "tok", "ua/1", "")
	if c.baseURL != "https://example.com" {
		t.Errorf("baseURL = %q, want https://example.com", c.baseURL)
	}
}

func TestNewAPIClient_StripsTrailingSlash(t *testing.T) {
	c := NewAPIClient("https://example.com/", "tok", "ua/1", "")
	if strings.HasSuffix(c.baseURL, "/") {
		t.Errorf("baseURL = %q still has trailing slash", c.baseURL)
	}
}

func TestNewAPIClient_StoresTokenAndUA(t *testing.T) {
	c := NewAPIClient("https://example.com", "secret-token", "my-agent/2", "")
	if c.token != "secret-token" {
		t.Errorf("token = %q, want secret-token", c.token)
	}
	if c.userAgent != "my-agent/2" {
		t.Errorf("userAgent = %q, want my-agent/2", c.userAgent)
	}
}

// ---------------------------------------------------------------------------
// Helper — fake server that routes by path
// ---------------------------------------------------------------------------

type routeMap map[string]http.HandlerFunc

func newTestServer(t *testing.T, routes routeMap) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, handler := range routes {
		mux.HandleFunc(path, handler)
	}
	return httptest.NewServer(mux)
}

func jsonHandler(v interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
}

func textHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}
}

func errorHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

// ---------------------------------------------------------------------------
// GetMyIP
// ---------------------------------------------------------------------------

func TestGetMyIP_ReturnsIP(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/ip": textHandler("203.0.113.1\n"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "test/1", "")
	got, err := c.GetMyIP(context.Background())
	if err != nil {
		t.Fatalf("GetMyIP: %v", err)
	}
	if got != "203.0.113.1" {
		t.Errorf("GetMyIP = %q, want 203.0.113.1", got)
	}
}

func TestGetMyIP_TrimsWhitespace(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/ip": textHandler("  192.168.1.1  \n"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	got, err := c.GetMyIP(context.Background())
	if err != nil {
		t.Fatalf("GetMyIP: %v", err)
	}
	if got != "192.168.1.1" {
		t.Errorf("GetMyIP = %q, want 192.168.1.1", got)
	}
}

func TestGetMyIP_ServerError(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/ip": errorHandler(http.StatusServiceUnavailable, "down"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	_, err := c.GetMyIP(context.Background())
	if err == nil {
		t.Fatal("expected error from 503, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetMyIPJSON
// ---------------------------------------------------------------------------

func TestGetMyIPJSON_DecodesResponse(t *testing.T) {
	payload := IPResponse{
		IP:         "203.0.113.1",
		Country:    "Elbonia",
		CountryISO: "EB",
		City:       "Bornyasherk",
	}
	srv := newTestServer(t, routeMap{
		"/json": jsonHandler(payload),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "test/1", "")
	got, err := c.GetMyIPJSON(context.Background())
	if err != nil {
		t.Fatalf("GetMyIPJSON: %v", err)
	}
	if got.IP != "203.0.113.1" {
		t.Errorf("IP = %q, want 203.0.113.1", got.IP)
	}
	if got.Country != "Elbonia" {
		t.Errorf("Country = %q, want Elbonia", got.Country)
	}
	if got.CountryISO != "EB" {
		t.Errorf("CountryISO = %q, want EB", got.CountryISO)
	}
}

func TestGetMyIPJSON_InvalidJSON(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/json": textHandler("not-json"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	_, err := c.GetMyIPJSON(context.Background())
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestGetMyIPJSON_ServerError(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/json": errorHandler(http.StatusInternalServerError, "oops"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	_, err := c.GetMyIPJSON(context.Background())
	if err == nil {
		t.Fatal("expected error from 500, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetIPJSON — specific IP lookup
// ---------------------------------------------------------------------------

func TestGetIPJSON_RoutesCorrectly(t *testing.T) {
	payload := IPResponse{IP: "1.2.3.4", Country: "Testland"}
	srv := newTestServer(t, routeMap{
		"/1.2.3.4/json": jsonHandler(payload),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	got, err := c.GetIPJSON(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("GetIPJSON: %v", err)
	}
	if got.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want 1.2.3.4", got.IP)
	}
}

func TestGetIPJSON_NotFound(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/9.9.9.9/json": errorHandler(http.StatusNotFound, "not found"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	_, err := c.GetIPJSON(context.Background(), "9.9.9.9")
	if err == nil {
		t.Fatal("expected error from 404, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetField
// ---------------------------------------------------------------------------

func TestGetField_ReturnsFieldValue(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/country": textHandler("Elbonia\n"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	got, err := c.GetField(context.Background(), "country")
	if err != nil {
		t.Fatalf("GetField: %v", err)
	}
	if got != "Elbonia" {
		t.Errorf("GetField = %q, want Elbonia", got)
	}
}

func TestGetField_ServerError(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/city": errorHandler(http.StatusBadRequest, "bad request"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	_, err := c.GetField(context.Background(), "city")
	if err == nil {
		t.Fatal("expected error from 400, got nil")
	}
}

// ---------------------------------------------------------------------------
// Autodiscover
// ---------------------------------------------------------------------------

func TestAutodiscover_DecodesResponse(t *testing.T) {
	payload := AutodiscoverResponse{
		ServerName: "ipgaze",
		Version:    "1.2.3",
		APIVersion: "v1",
		BaseURL:    "https://ifcfg.us",
		CLIVersions: map[string]CLIVersionEntry{
			"linux-amd64": {Version: "1.2.3", SHA256: "abc123"},
		},
		CLIMinVersion: "1.0.0",
	}
	srv := newTestServer(t, routeMap{
		"/api/autodiscover": jsonHandler(payload),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "test/1", "")
	got, err := c.Autodiscover(context.Background())
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if got.ServerName != "ipgaze" {
		t.Errorf("ServerName = %q, want ipgaze", got.ServerName)
	}
	if got.Version != "1.2.3" {
		t.Errorf("Version = %q, want 1.2.3", got.Version)
	}
	entry, ok := got.CLIVersions["linux-amd64"]
	if !ok {
		t.Fatal("missing linux-amd64 in CLIVersions")
	}
	if entry.SHA256 != "abc123" {
		t.Errorf("SHA256 = %q, want abc123", entry.SHA256)
	}
	if got.CLIMinVersion != "1.0.0" {
		t.Errorf("CLIMinVersion = %q, want 1.0.0", got.CLIMinVersion)
	}
}

func TestAutodiscover_BadJSON(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/api/autodiscover": textHandler("garbage"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	_, err := c.Autodiscover(context.Background())
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestAutodiscover_ServerError(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/api/autodiscover": errorHandler(http.StatusUnauthorized, "unauthorized"),
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "bad-tok", "", "")
	_, err := c.Autodiscover(context.Background())
	if err == nil {
		t.Fatal("expected error from 401, got nil")
	}
}

// ---------------------------------------------------------------------------
// Authorization header propagation
// ---------------------------------------------------------------------------

func TestDoAPIRequest_SendsBearerToken(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, "my-token", "", "")
	_, _ = c.GetMyIP(context.Background())

	if capturedAuth != "Bearer my-token" {
		t.Errorf("Authorization = %q, want Bearer my-token", capturedAuth)
	}
}

func TestDoAPIRequest_NoAuthHeaderWhenNoToken(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "127.0.0.1")
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "", "")
	_, _ = c.GetMyIP(context.Background())

	if capturedAuth != "" {
		t.Errorf("Authorization = %q, want empty (no token)", capturedAuth)
	}
}

func TestDoAPIRequest_SendsUserAgent(t *testing.T) {
	var capturedUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, "127.0.0.1")
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "myagent/3.0", "")
	_, _ = c.GetMyIP(context.Background())

	if capturedUA != "myagent/3.0" {
		t.Errorf("User-Agent = %q, want myagent/3.0", capturedUA)
	}
}

// ---------------------------------------------------------------------------
// TOKEN_REVOKED detection
// ---------------------------------------------------------------------------

func TestDoAPIRequest_PlainTextTokenRevoked(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/ip": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "TOKEN_REVOKED")
		},
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "old-token", "", "")
	_, err := c.GetMyIP(context.Background())
	if err != ErrTokenRevoked {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestDoAPIRequest_JSONTokenRevoked(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/json": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"TOKEN_REVOKED"}`)
		},
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "old-token", "", "")
	_, err := c.GetMyIPJSON(context.Background())
	if err != ErrTokenRevoked {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestDoAPIRequest_OtherUnauthorizedNotRevoked(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/ip": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_token"}`)
		},
	})
	defer srv.Close()

	c := NewAPIClient(srv.URL, "bad-token", "", "")
	_, err := c.GetMyIP(context.Background())
	if err == ErrTokenRevoked {
		t.Error("got ErrTokenRevoked for non-revocation 401, want generic error")
	}
	if err == nil {
		t.Error("expected error from 401, got nil")
	}
}

// ---------------------------------------------------------------------------
// isTokenRevoked unit tests (package-internal function)
// ---------------------------------------------------------------------------

func TestIsTokenRevoked_PlainText(t *testing.T) {
	if !isTokenRevoked([]byte("TOKEN_REVOKED")) {
		t.Error("expected true for plain TOKEN_REVOKED")
	}
}

func TestIsTokenRevoked_PlainTextWithWhitespace(t *testing.T) {
	if !isTokenRevoked([]byte("  TOKEN_REVOKED  ")) {
		t.Error("expected true for TOKEN_REVOKED with surrounding whitespace")
	}
}

func TestIsTokenRevoked_JSONError(t *testing.T) {
	if !isTokenRevoked([]byte(`{"error":"TOKEN_REVOKED"}`)) {
		t.Error(`expected true for {"error":"TOKEN_REVOKED"}`)
	}
}

func TestIsTokenRevoked_OtherJSONError(t *testing.T) {
	if isTokenRevoked([]byte(`{"error":"invalid_credentials"}`)) {
		t.Error("expected false for non-TOKEN_REVOKED JSON error")
	}
}

func TestIsTokenRevoked_RandomBody(t *testing.T) {
	if isTokenRevoked([]byte("Internal Server Error")) {
		t.Error("expected false for generic error text")
	}
}

func TestIsTokenRevoked_EmptyBody(t *testing.T) {
	if isTokenRevoked([]byte("")) {
		t.Error("expected false for empty body")
	}
}

// ---------------------------------------------------------------------------
// DownloadBinary
// ---------------------------------------------------------------------------

func TestDownloadBinary_WritesContentsToFile(t *testing.T) {
	content := []byte("fake binary data 1234")
	srv := newTestServer(t, routeMap{
		"/cli/binaries/testbin": func(w http.ResponseWriter, r *http.Request) {
			w.Write(content)
		},
	})
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "testbin.out")
	c := NewAPIClient(srv.URL, "tok", "ua", "")
	n, err := c.DownloadBinary(context.Background(), "testbin", dst)
	if err != nil {
		t.Fatalf("DownloadBinary: %v", err)
	}
	if n != int64(len(content)) {
		t.Errorf("bytes written = %d, want %d", n, len(content))
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("file content = %q, want %q", got, content)
	}
}

func TestDownloadBinary_404ReturnsError(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/cli/binaries/missing": errorHandler(http.StatusNotFound, "not found"),
	})
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "missing.out")
	c := NewAPIClient(srv.URL, "", "", "")
	_, err := c.DownloadBinary(context.Background(), "missing", dst)
	if err == nil {
		t.Fatal("expected error from 404, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error %q does not mention 404", err.Error())
	}
}

func TestDownloadBinary_500ReturnsError(t *testing.T) {
	srv := newTestServer(t, routeMap{
		"/cli/binaries/bad": errorHandler(http.StatusInternalServerError, "server error"),
	})
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "bad.out")
	c := NewAPIClient(srv.URL, "", "", "")
	_, err := c.DownloadBinary(context.Background(), "bad", dst)
	if err == nil {
		t.Fatal("expected error from 500, got nil")
	}
}

func TestDownloadBinary_SendsAuthToken(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Write([]byte("data"))
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "dl.out")
	c := NewAPIClient(srv.URL, "dl-token", "", "")
	_, _ = c.DownloadBinary(context.Background(), "anything", dst)

	if capturedAuth != "Bearer dl-token" {
		t.Errorf("Authorization = %q, want Bearer dl-token", capturedAuth)
	}
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

func TestGetMyIP_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't respond — the client should time out or be cancelled
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewAPIClient(srv.URL, "", "", "")
	_, err := c.GetMyIP(ctx)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}

// ---------------------------------------------------------------------------
// URL encoding — user input must never be interpolated raw into the path
// (AI.md PART 32: "ALL user input in URLs MUST be encoded")
// ---------------------------------------------------------------------------

// captureRequestURI starts a test server that records the raw request URI of
// every request it receives and always answers with an empty JSON object.
func captureRequestURI(t *testing.T, recorded *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*recorded = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ip":"1.2.3.4"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGetIPJSON_EncodesPathTraversalPayload(t *testing.T) {
	var got string
	srv := captureRequestURI(t, &got)
	c := NewAPIClient(srv.URL, "", "ua/1", "")

	payload := "../../server/admin/tokens"
	if _, err := c.GetIPJSON(context.Background(), payload); err != nil {
		t.Fatalf("GetIPJSON: %v", err)
	}

	if strings.Contains(got, "..") && strings.Contains(got, "/server/admin") {
		t.Fatalf("path traversal payload was interpolated raw: %q", got)
	}
	want := "/" + url.PathEscape(payload) + "/json"
	if got != want {
		t.Errorf("request path = %q, want %q", got, want)
	}
}

func TestGetIPJSON_EncodesQueryInjectionPayload(t *testing.T) {
	var got string
	srv := captureRequestURI(t, &got)
	c := NewAPIClient(srv.URL, "", "ua/1", "")

	payload := "8.8.8.8?admin=true#frag"
	if _, err := c.GetIPJSON(context.Background(), payload); err != nil {
		t.Fatalf("GetIPJSON: %v", err)
	}
	if strings.Contains(got, "?") || strings.Contains(got, "#") {
		t.Fatalf("query/fragment injection reached the server unencoded: %q", got)
	}
}

func TestGetIPField_EncodesAndNormalizes(t *testing.T) {
	var got string
	srv := captureRequestURI(t, &got)
	c := NewAPIClient(srv.URL, "", "ua/1", "")

	if _, err := c.GetIPField(context.Background(), "8.8.8.8", "country-iso"); err != nil {
		t.Fatalf("GetIPField: %v", err)
	}
	if got != "/8.8.8.8/country_iso" {
		t.Errorf("request path = %q, want /8.8.8.8/country_iso", got)
	}
}

func TestGetIPField_EncodesTraversalInField(t *testing.T) {
	var got string
	srv := captureRequestURI(t, &got)
	c := NewAPIClient(srv.URL, "", "ua/1", "")

	if _, err := c.GetIPField(context.Background(), "8.8.8.8", "../../etc/passwd"); err != nil {
		t.Fatalf("GetIPField: %v", err)
	}
	if strings.Contains(got, "/etc/passwd") {
		t.Fatalf("traversal payload was interpolated raw: %q", got)
	}
}

func TestNormalizeFieldName(t *testing.T) {
	cases := map[string]string{
		"country-iso": "country_iso",
		"asn-org":     "asn_org",
		"ip":          "ip",
		"time-zone":   "time_zone",
	}
	for in, want := range cases {
		if got := normalizeFieldName(in); got != want {
			t.Errorf("normalizeFieldName(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Typed errors — status code classification for exit-code mapping
// ---------------------------------------------------------------------------

func TestAPIError_Classification(t *testing.T) {
	cases := []struct {
		status       int
		unauthorized bool
		notFound     bool
	}{
		{http.StatusUnauthorized, true, false},
		{http.StatusForbidden, true, false},
		{http.StatusNotFound, false, true},
		{http.StatusInternalServerError, false, false},
	}
	for _, c := range cases {
		err := error(&APIError{StatusCode: c.status})
		if got := IsUnauthorized(err); got != c.unauthorized {
			t.Errorf("IsUnauthorized(%d) = %v, want %v", c.status, got, c.unauthorized)
		}
		if got := IsNotFound(err); got != c.notFound {
			t.Errorf("IsNotFound(%d) = %v, want %v", c.status, got, c.notFound)
		}
		if IsConnectionError(err) {
			t.Errorf("IsConnectionError(%d) = true, want false", c.status)
		}
	}
}

func TestConnectionError_Classification(t *testing.T) {
	c := NewAPIClient("http://127.0.0.1:1", "", "ua/1", "")
	_, err := c.GetMyIPJSON(context.Background())
	if err == nil {
		t.Fatal("expected a connection error against a closed port")
	}
	if !IsConnectionError(err) {
		t.Errorf("IsConnectionError(%v) = false, want true", err)
	}
	if IsUnauthorized(err) || IsNotFound(err) {
		t.Errorf("connection error misclassified as HTTP status error: %v", err)
	}
}

func TestDoAPIRequest_ReturnsTypedAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, "", "ua/1", "")
	_, err := c.GetMyIPJSON(context.Background())
	if err == nil {
		t.Fatal("expected an error for a 404 response")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", apiErr.StatusCode)
	}
}
