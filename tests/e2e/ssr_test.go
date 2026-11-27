//go:build e2e

// Tier 1 of AI.md PART 28 "Browser E2E Testing": server-side rendering
// correctness, proven with a plain net/http client and no browser at all.
// Every assertion here is about the bytes the server puts on the wire in the
// first response — real domain data, correct status codes, complete document
// head — because an empty shell that JavaScript fills in later is a PART 14
// violation, not a passing page.
package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// assetRefPattern extracts href/src targets from rendered HTML so the suite
// can prove every asset the page references is actually served.
var assetRefPattern = regexp.MustCompile(`(?:href|src)="([^"]+)"`)

// ipInElementPattern pulls the rendered visitor IP out of the landing page's
// dedicated element.
var ipInElementPattern = regexp.MustCompile(`(?s)<code[^>]*id="ip-address"[^>]*>(.*?)</code>`)

// csrfFieldPattern pulls the hidden CSRF token out of a rendered form.
var csrfFieldPattern = regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`)

func ownerTokenAPICall(t *testing.T, method, path, bearer string, payload any) (int, []byte) {
	t.Helper()
	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("encoding %s request: %v", path, err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		t.Fatalf("building %s request: %v", path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", browserUserAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("requesting %s: %v", path, err)
	}
	defer res.Body.Close()
	response, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading %s response: %v", path, err)
	}
	return res.StatusCode, response
}

func ownerTokenResponseField(t *testing.T, body []byte, field string) string {
	t.Helper()
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("token API response is not JSON: %v", err)
	}
	data := envelope["data"]
	if len(data) == 0 {
		data = body
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("token API data is not an object: %v", err)
	}
	var value string
	if err := json.Unmarshal(result[field], &value); err != nil || value == "" {
		t.Fatalf("token API response has no %q field", field)
	}
	return value
}

func mcpLookupStatus(t *testing.T, token string) int {
	t.Helper()
	requestBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":"v1IpLookup","arguments":{"ip":"8.8.8.8"}}}`
	req, err := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(requestBody))
	if err != nil {
		t.Fatalf("building MCP lookup request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "v1IpLookup")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("calling the MCP lookup tool: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusBadRequest {
		body, readErr := io.ReadAll(res.Body)
		if readErr != nil {
			t.Logf("MCP lookup returned %d (could not read response body: %v)", res.StatusCode, readErr)
		} else {
			t.Logf("MCP lookup returned %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
		}
	}
	return res.StatusCode
}

func TestSSROwnerTokenIssueAndManagementAPI(t *testing.T) {
	const base = "/api/v1/server/preferences/tokens"
	if status := mcpLookupStatus(t, ""); status != http.StatusUnauthorized {
		t.Errorf("MCP lookup without a token returned %d, want 401", status)
	}
	status, body := ownerTokenAPICall(t, http.MethodPost, base+"/primary", "", nil)
	if status != http.StatusCreated {
		t.Fatalf("issuing an anonymous owner token returned %d: %s", status, body)
	}
	primary := ownerTokenResponseField(t, body, "owner_token")
	if status := mcpLookupStatus(t, primary); status != http.StatusOK {
		t.Errorf("MCP lookup with the primary owner token returned %d, want 200", status)
	}

	status, _ = ownerTokenAPICall(t, http.MethodPost, base+"/primary", primary, nil)
	if status != http.StatusConflict {
		t.Errorf("issuing a second primary token with a valid owner token returned %d, want 409", status)
	}
	status, _ = ownerTokenAPICall(t, http.MethodGet, base, "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("listing tokens without a bearer token returned %d, want 401", status)
	}
	status, _ = ownerTokenAPICall(t, http.MethodGet, base, primary, nil)
	if status != http.StatusOK {
		t.Fatalf("listing tokens with the primary token returned %d, want 200", status)
	}

	status, body = ownerTokenAPICall(t, http.MethodPost, base, primary, map[string]string{"name": "e2e-client", "expires": "7d"})
	if status != http.StatusCreated {
		t.Fatalf("creating a linked token returned %d: %s", status, body)
	}
	linked := ownerTokenResponseField(t, body, "linked_token")
	linkedID := ownerTokenResponseField(t, body, "id")
	if status := mcpLookupStatus(t, linked); status != http.StatusOK {
		t.Errorf("MCP lookup with a linked owner token returned %d, want 200", status)
	}
	status, _ = ownerTokenAPICall(t, http.MethodGet, base, linked, nil)
	if status != http.StatusForbidden {
		t.Errorf("linked token accessed primary-only token management with status %d, want 403", status)
	}
	status, body = ownerTokenAPICall(t, http.MethodPatch, base+"/"+linkedID, primary, map[string]string{"name": "e2e-client-renamed", "expires": "30d"})
	if status != http.StatusOK || !bytes.Contains(body, []byte("e2e-client-renamed")) {
		t.Fatalf("renaming a linked token returned %d or omitted the new name: %s", status, body)
	}
	status, body = ownerTokenAPICall(t, http.MethodPost, base+"/"+linkedID+"/reveal", primary, nil)
	if status != http.StatusOK || ownerTokenResponseField(t, body, "linked_token") != linked {
		t.Fatalf("revealing the linked token returned %d or a different token: %s", status, body)
	}
	status, body = ownerTokenAPICall(t, http.MethodPost, base+"/"+linkedID+"/rotate", primary, nil)
	if status != http.StatusOK {
		t.Fatalf("rotating the linked token returned %d: %s", status, body)
	}
	rotatedLinked := ownerTokenResponseField(t, body, "linked_token")
	if rotatedLinked == linked {
		t.Fatal("rotating the linked token returned the old credential")
	}
	if status := mcpLookupStatus(t, linked); status != http.StatusUnauthorized {
		t.Errorf("old linked token remained accepted after rotation (status %d)", status)
	}
	if status := mcpLookupStatus(t, rotatedLinked); status != http.StatusOK {
		t.Errorf("rotated linked token was not accepted (status %d)", status)
	}
	status, _ = ownerTokenAPICall(t, http.MethodGet, base, linked, nil)
	if status != http.StatusUnauthorized {
		t.Errorf("linked token accessed primary-only token management with status %d, want 403", status)
	}
	status, body = ownerTokenAPICall(t, http.MethodPost, base+"/primary/rotate", primary, nil)
	if status != http.StatusOK {
		t.Fatalf("rotating the primary token returned %d: %s", status, body)
	}
	rotatedPrimary := ownerTokenResponseField(t, body, "owner_token")
	if rotatedPrimary == primary {
		t.Fatal("rotating the primary token returned the old credential")
	}
	status, _ = ownerTokenAPICall(t, http.MethodGet, base, primary, nil)
	if status != http.StatusUnauthorized {
		t.Errorf("old primary token remained valid after rotation (status %d)", status)
	}
	status, _ = ownerTokenAPICall(t, http.MethodGet, base, rotatedPrimary, nil)
	if status != http.StatusOK {
		t.Errorf("rotated primary token cannot manage its tokens (status %d)", status)
	}
	if status := mcpLookupStatus(t, rotatedLinked); status != http.StatusOK {
		t.Errorf("rotating the primary token invalidated a linked token (status %d)", status)
	}
	status, body = ownerTokenAPICall(t, http.MethodDelete, base+"/"+linkedID, rotatedPrimary, nil)
	if status != http.StatusOK {
		t.Errorf("revoking the linked token returned %d: %s", status, body)
	}
	if status := mcpLookupStatus(t, rotatedLinked); status != http.StatusUnauthorized {
		t.Errorf("revoked linked token remained accepted by MCP (status %d)", status)
	}

	pageResponse := browserRequest(t, http.MethodGet, "/server/preferences/tokens", nil)
	page, readErr := io.ReadAll(pageResponse.Body)
	if readErr != nil {
		t.Fatalf("reading restore page: %v", readErr)
	}
	pageResponse.Body.Close()
	csrf := csrfFieldPattern.FindSubmatch(page)
	if csrf == nil {
		t.Fatal("owner-token restore page has no CSRF form token")
	}
	form := url.Values{"csrf_token": {string(csrf[1])}, "token": {rotatedPrimary}}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/server/preferences/token/restore", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("building owner-token restore request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "csrf_token="+string(csrf[1]))
	req.Header.Set("User-Agent", browserUserAgent)
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	restored, err := client.Do(req)
	if err != nil {
		t.Fatalf("restoring the primary owner token: %v", err)
	}
	restored.Body.Close()
	if restored.StatusCode != http.StatusSeeOther {
		t.Fatalf("restoring a valid primary token returned %d, want 303", restored.StatusCode)
	}
	restoredCookie := ""
	for _, cookie := range restored.Cookies() {
		if strings.HasPrefix(cookie.Name, "ipgaze_owner_token_") && cookie.Value == rotatedPrimary {
			restoredCookie = cookie.Name + "=" + cookie.Value
		}
	}
	if restoredCookie == "" {
		t.Fatal("restoring a valid primary token did not set the owner cookie")
	}
	ownedPage, ownedBody, _ := getBody(t, "/server/preferences/tokens", http.Header{"Cookie": []string{restoredCookie}})
	if ownedPage != http.StatusOK || !strings.Contains(ownedBody, "e2e-client-renamed") {
		t.Errorf("restored owner cookie did not unlock the token list (status %d)", ownedPage)
	}

	anonymousPageStatus, anonymousPageBody, _ := getBody(t, "/server/preferences/tokens", nil)
	if anonymousPageStatus != http.StatusOK {
		t.Fatalf("anonymous owner-token page returned %d, want 200", anonymousPageStatus)
	}
	mustContain(t, "tokens.html", anonymousPageBody, `action="/server/preferences/token/restore"`, "public restore form")
	if strings.Contains(anonymousPageBody, primary) || strings.Contains(anonymousPageBody, rotatedPrimary) || strings.Contains(anonymousPageBody, rotatedLinked) {
		t.Error("public owner-token page disclosed an API credential without its owner cookie")
	}
}

func TestSSRLandingPageRendersRealIPAndContent(t *testing.T) {
	status, body, header := getBody(t, "/", nil)
	if status != http.StatusOK {
		t.Fatalf("GET / returned %d, want 200", status)
	}
	if ct := header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("GET / Content-Type is %q, want text/html", ct)
	}

	mustContain(t, "index.html", body, `<html lang="en"`, "landing page <html> lang attribute")
	mustContain(t, "index.html", body, `<meta charset="utf-8"`, "landing page charset meta")
	mustContain(t, "index.html", body, `name="viewport"`, "landing page viewport meta")
	mustContain(t, "index.html", body, `<title>What is my IP address?`, "landing page title")
	mustContain(t, "index.html", body, "What is my IP address?</h1>", "landing page h1")
	mustContain(t, "index.html", body, "What do we know about this IP address?", "landing page detail column heading")
	mustContain(t, "index.html", body, ">IP Address</th>", "landing page IP table row")

	// The rendered IP must be a real, parseable address present in the very
	// first response — not a placeholder waiting on client-side JavaScript.
	match := ipInElementPattern.FindStringSubmatch(body)
	if match == nil {
		saveArtifact(t, "index.html", []byte(body))
		t.Fatal("landing page has no #ip-address element in the server-rendered HTML")
	}
	rendered := strings.TrimSpace(match[1])
	if net.ParseIP(rendered) == nil {
		saveArtifact(t, "index.html", []byte(body))
		t.Fatalf("#ip-address rendered %q, which is not a valid IP address", rendered)
	}

	// The same request must not be an empty client-rendered shell.
	for _, shell := range []string{`<div id="app"></div>`, `<div id="root"></div>`} {
		if strings.Contains(body, shell) {
			saveArtifact(t, "index.html", []byte(body))
			t.Errorf("landing page contains client-side-only shell %q", shell)
		}
	}
}

func TestSSRLandingPageMatchesJSONForSameVisitor(t *testing.T) {
	_, html, _ := getBody(t, "/", nil)
	match := ipInElementPattern.FindStringSubmatch(html)
	if match == nil {
		t.Fatal("landing page has no #ip-address element")
	}
	renderedIP := strings.TrimSpace(match[1])

	status, body, _ := getBody(t, "/json", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /json returned %d, want 200", status)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("GET /json is not valid JSON: %v", err)
	}
	if payload["ip"] != renderedIP {
		t.Errorf("GET /json reports ip=%v but the HTML page rendered %q", payload["ip"], renderedIP)
	}

	status, plain, _ := getBody(t, "/ip.txt", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /ip.txt returned %d, want 200", status)
	}
	if strings.TrimSpace(plain) != renderedIP {
		t.Errorf("GET /ip.txt returned %q, want %q", strings.TrimSpace(plain), renderedIP)
	}
}

func TestSSRSpecificIPLookupReturnsThatIP(t *testing.T) {
	const target = "8.8.8.8"

	status, body, _ := getBody(t, "/"+target, http.Header{"Accept": []string{"application/json"}})
	if status != http.StatusOK {
		t.Fatalf("GET /%s returned %d, want 200", target, status)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("GET /%s is not valid JSON: %v", target, err)
	}
	if payload["ip"] != target {
		t.Errorf("GET /%s reports ip=%v, want %q", target, payload["ip"], target)
	}

	status, field, _ := getBody(t, "/"+target+"/ip", http.Header{"Accept": []string{"text/plain"}})
	if status != http.StatusOK {
		t.Fatalf("GET /%s/ip returned %d, want 200", target, status)
	}
	if strings.TrimSpace(field) != target {
		t.Errorf("GET /%s/ip returned %q, want %q", target, strings.TrimSpace(field), target)
	}

	status, apiBody, _ := getBody(t, "/api/v1/ip/"+target, http.Header{"Accept": []string{"application/json"}})
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/ip/%s returned %d, want 200", target, status)
	}
	var apiPayload map[string]any
	if err := json.Unmarshal([]byte(apiBody), &apiPayload); err != nil {
		t.Fatalf("GET /api/v1/ip/%s is not valid JSON: %v", target, err)
	}
	if apiPayload["ip"] != target {
		t.Errorf("GET /api/v1/ip/%s reports ip=%v, want %q", target, apiPayload["ip"], target)
	}
}

func TestSSRContentNegotiationHonoursClient(t *testing.T) {
	_, htmlBody, htmlHeader := getBody(t, "/", nil)
	if !strings.Contains(htmlHeader.Get("Content-Type"), "text/html") {
		t.Errorf("browser request to / did not get HTML, got %q", htmlHeader.Get("Content-Type"))
	}
	if !strings.Contains(htmlBody, "<html") {
		t.Error("browser request to / returned a body without an <html> element")
	}

	_, jsonBody, jsonHeader := getBody(t, "/", http.Header{"Accept": []string{"application/json"}})
	if !strings.Contains(jsonHeader.Get("Content-Type"), "application/json") {
		t.Errorf("Accept: application/json on / returned Content-Type %q", jsonHeader.Get("Content-Type"))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(jsonBody), &payload); err != nil {
		t.Fatalf("Accept: application/json on / is not valid JSON: %v", err)
	}
	if payload["ip"] == nil {
		t.Error("Accept: application/json on / returned JSON without an ip field")
	}

	_, curlBody, _ := getBody(t, "/", http.Header{"User-Agent": []string{"curl/8.5.0"}, "Accept": []string{"*/*"}})
	if strings.Contains(strings.ToLower(curlBody), "<html") {
		t.Error("curl user-agent on / returned HTML instead of plain text")
	}
	if strings.TrimSpace(curlBody) == "" {
		t.Error("curl user-agent on / returned an empty body")
	}
}

func TestSSRPlainTextFieldEndpoints(t *testing.T) {
	for _, path := range []string{"/ip", "/ip.txt"} {
		status, body, header := getBody(t, path, nil)
		if status != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200", path, status)
			continue
		}
		if ct := header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
			t.Errorf("GET %s Content-Type is %q, want text/plain", path, ct)
		}
		if strings.Contains(strings.ToLower(body), "<html") {
			t.Errorf("GET %s returned HTML on a plain-text endpoint", path)
		}
	}
	// The harness connects from loopback. AI.md PART 19 requires private and
	// internal addresses to bypass GeoIP lookup, so the registered field routes
	// return an empty plain-text value rather than geolocating the client.
	for _, path := range []string{"/country.txt", "/country-iso.txt", "/city.txt", "/coordinates.txt", "/asn.txt", "/asn-org.txt"} {
		status, body, _ := getBody(t, path, nil)
		if status != http.StatusOK {
			t.Errorf("GET %s returned %d for the private test client IP, want 200", path, status)
		}
		if strings.TrimSpace(body) != "" {
			t.Errorf("GET %s returned GeoIP data for the private test client IP: %q", path, body)
		}
	}
}

func TestSSRStandardServerPagesRender(t *testing.T) {
	cases := []struct {
		path     string
		title    string
		fragment string
	}{
		{"/server/about", "<title>About — ", "About — "},
		{"/server/help", "<title>", "<h1"},
		{"/server/privacy", "<title>", "<h1"},
		{"/server/terms", "<title>", "<h1"},
		{"/server/contact", "<title>", "<form"},
		{"/server/preferences", "<title>Preferences — ", "more-preferences"},
		{"/server/preferences/sync", "<title>Preference sync — ", "preferences-export-code"},
		{"/server/healthz", "<title>", "status-banner"},
	}
	for _, tc := range cases {
		status, body, header := getBody(t, tc.path, nil)
		if status != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200", tc.path, status)
			continue
		}
		if ct := header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("GET %s Content-Type is %q, want text/html", tc.path, ct)
		}
		artifact := strings.ReplaceAll(strings.TrimPrefix(tc.path, "/"), "/", "-") + ".html"
		mustContain(t, artifact, body, tc.title, "title of "+tc.path)
		mustContain(t, artifact, body, tc.fragment, "content of "+tc.path)
		mustContain(t, artifact, body, `<html lang="en"`, "lang attribute of "+tc.path)
		mustContain(t, artifact, body, `name="viewport"`, "viewport meta of "+tc.path)
	}
}

func TestSSRServerIndexRedirectsToAbout(t *testing.T) {
	res := browserRequest(t, http.MethodGet, "/server", nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("GET /server returned %d, want 301", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/server/about" {
		t.Errorf("GET /server redirected to %q, want /server/about", loc)
	}
}

func TestSSRInvalidSecurityReportRendersNotFoundPage(t *testing.T) {
	status, body, header := getBody(t, "/server/security/report/invalid-tracking-id", nil)
	if status != http.StatusNotFound {
		t.Fatalf("invalid security report returned %d, want 404", status)
	}
	if !strings.Contains(header.Get("Content-Type"), "text/html") {
		t.Errorf("invalid security report Content-Type is %q, want text/html", header.Get("Content-Type"))
	}
	mustContain(t, "security-report-not-found.html", body, `<main id="main-content"`, "themed not-found main landmark")
}

func TestSSRUnknownPathRendersThemedErrorPage(t *testing.T) {
	status, body, header := getBody(t, "/this-page-does-not-exist", nil)
	if status != http.StatusNotFound {
		t.Fatalf("GET /this-page-does-not-exist returned %d, want 404", status)
	}
	if ct := header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("404 Content-Type is %q, want text/html", ct)
	}
	mustContain(t, "404.html", body, `class="page-title">404 Not Found`, "404 page title element")
	mustContain(t, "404.html", body, `class="section-card"`, "404 page error container")
	mustContain(t, "404.html", body, `href="/"`, "404 page return-home link")
	for _, leak := range []string{"goroutine ", "/root/", "panic:"} {
		if strings.Contains(body, leak) {
			saveArtifact(t, "404.html", []byte(body))
			t.Errorf("404 page leaks internals: found %q", leak)
		}
	}
}

func TestSSRDebugError500RendersThemedPage(t *testing.T) {
	header := make(http.Header)
	header.Set("Authorization", "Bearer e2e-debug-token")
	status, body, responseHeader := getBody(t, "/debug/error500", header)
	if status != http.StatusInternalServerError {
		t.Fatalf("GET /debug/error500 returned %d, want 500; body=%s", status, body)
	}
	if ct := responseHeader.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("debug 500 Content-Type is %q, want text/html", ct)
	}
	mustContain(t, "debug-error500.html", body, `class="page-title">500 Internal Server Error`, "themed 500 page title")
	mustContain(t, "debug-error500.html", body, `class="section-card"`, "themed 500 page container")
}

func TestSSRWellKnownAndMetadataEndpoints(t *testing.T) {
	cases := []struct {
		path     string
		fragment string
	}{
		{"/robots.txt", "User-agent"},
		{"/.well-known/security.txt", "Contact"},
		{"/llms.txt", "ipgaze"},
	}
	for _, tc := range cases {
		status, body, _ := getBody(t, tc.path, nil)
		if status != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200", tc.path, status)
			continue
		}
		if !strings.Contains(body, tc.fragment) {
			t.Errorf("GET %s does not contain %q", tc.path, tc.fragment)
		}
	}

	status, body, _ := getBody(t, "/manifest.json", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /manifest.json returned %d, want 200", status)
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(body), &manifest); err != nil {
		t.Fatalf("GET /manifest.json is not valid JSON: %v", err)
	}
	if manifest["name"] == nil || manifest["start_url"] == nil {
		t.Errorf("manifest.json is missing name or start_url: %v", manifest)
	}
}

func TestSSRAPIDocsPagesRender(t *testing.T) {
	status, swagger, _ := getBody(t, "/server/docs/swagger", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /server/docs/swagger returned %d, want 200", status)
	}
	mustContain(t, "swagger.html", swagger, `id="swagger-ui"`, "swagger UI mount point")
	mustContain(t, "swagger.html", swagger, "/static/vendor/swagger-ui/swagger-ui.css", "vendored swagger stylesheet")

	status, graphiql, _ := getBody(t, "/server/docs/graphql", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /server/docs/graphql returned %d, want 200", status)
	}
	mustContain(t, "graphiql.html", graphiql, "GraphQL", "GraphiQL explorer page")

	status, spec, _ := getBody(t, "/api/swagger", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/swagger returned %d, want 200", status)
	}
	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal([]byte(spec), &doc); err != nil {
		t.Fatalf("GET /api/swagger is not valid JSON: %v", err)
	}
	if doc.OpenAPI == "" {
		t.Error("OpenAPI spec has no openapi version field")
	}

	// Every documented path must be a route the server actually serves —
	// a spec that advertises endpoints the router does not have is a lie
	// to every API consumer.
	documented := make([]string, 0, len(doc.Paths))
	for path := range doc.Paths {
		documented = append(documented, path)
	}
	sort.Strings(documented)
	if len(documented) == 0 {
		t.Fatal("OpenAPI spec documents no paths at all")
	}
	optionalWhenUnconfigured := map[string]bool{
		"/.well-known/pgp-key.asc": true,
		"/server/tracking.js":      true,
		"/asn":                     true,
		"/asn-org":                 true,
		"/asn-org.txt":             true,
		"/asn.txt":                 true,
		"/api/v1/asn":              true,
		"/api/v1/asn-org":          true,
		"/api/v1/city":             true,
		"/api/v1/coordinates":      true,
		"/api/v1/country":          true,
		"/api/v1/country-iso":      true,
		"/city":                    true,
		"/city.txt":                true,
		"/coordinates":             true,
		"/coordinates.txt":         true,
		"/country":                 true,
		"/country-iso":             true,
		"/country-iso.txt":         true,
		"/country.txt":             true,
	}
	for _, path := range documented {
		if strings.Contains(path, "{") {
			path = strings.NewReplacer("{ip}", "8.8.8.8", "{field}", "ip").Replace(path)
			if strings.Contains(path, "{") {
				continue
			}
		}
		res := browserRequest(t, http.MethodGet, path, nil)
		res.Body.Close()
		if res.StatusCode == http.StatusNotFound && !optionalWhenUnconfigured[path] {
			t.Errorf("OpenAPI spec documents %s but the server returns 404 for it", path)
		}
	}
	status, _, _ = getBody(t, "/security.txt", nil)
	if status != http.StatusNotFound {
		t.Errorf("GET /security.txt returned %d, want 404", status)
	}
}

func TestSSRSwaggerUISpecURLResolves(t *testing.T) {
	_, page, _ := getBody(t, "/server/docs/swagger", nil)
	specAttr := regexp.MustCompile(`data-spec-url="([^"]+)"`).FindStringSubmatch(page)
	if specAttr == nil {
		t.Fatal("swagger UI page has no data-spec-url attribute")
	}
	parsed, err := url.Parse(specAttr[1])
	if err != nil {
		t.Fatalf("swagger UI data-spec-url %q is not a URL: %v", specAttr[1], err)
	}
	status, body, _ := getBody(t, parsed.Path, http.Header{"Accept": []string{"application/json"}})
	if status != http.StatusOK {
		t.Fatalf("swagger UI points at %s but that path returns %d — the interactive docs cannot load their spec", parsed.Path, status)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("swagger UI spec at %s is not valid JSON: %v", parsed.Path, err)
	}
}

func TestSSRReferencedStaticAssetsAllLoad(t *testing.T) {
	pages := []string{"/", "/server/about", "/server/preferences", "/server/healthz"}
	seen := map[string]bool{}
	for _, page := range pages {
		_, body, _ := getBody(t, page, nil)
		for _, match := range assetRefPattern.FindAllStringSubmatch(body, -1) {
			ref := match[1]
			if !strings.HasPrefix(ref, "/static/") && ref != "/manifest.json" && ref != "/sw.js" {
				continue
			}
			if seen[ref] {
				continue
			}
			seen[ref] = true
			res := browserRequest(t, http.MethodGet, ref, nil)
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Errorf("%s references %s which returns %d", page, ref, res.StatusCode)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no static assets were referenced by any page — the templates are not rendering their head")
	}
}

func TestSSRCrawlFollowsEveryInternalLink(t *testing.T) {
	queue := []string{"/"}
	visited := map[string]bool{}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if visited[current] {
			continue
		}
		visited[current] = true

		res := browserRequest(t, http.MethodGet, current, nil)
		body := ""
		if res.StatusCode == http.StatusOK && strings.Contains(res.Header.Get("Content-Type"), "text/html") {
			buf := make([]byte, 512*1024)
			n, _ := res.Body.Read(buf)
			body = string(buf[:n])
		}
		res.Body.Close()

		if res.StatusCode >= 500 {
			t.Errorf("crawl: %s returned %d", current, res.StatusCode)
			continue
		}
		if res.StatusCode == http.StatusNotFound {
			t.Errorf("crawl: %s is linked from the site but returns 404", current)
			continue
		}
		if body == "" {
			continue
		}
		for _, match := range assetRefPattern.FindAllStringSubmatch(body, -1) {
			next, ok := crawlableTarget(match[1])
			if ok && !visited[next] {
				queue = append(queue, next)
			}
		}
	}
	if len(visited) < 5 {
		t.Fatalf("crawl only reached %d pages (%v) — the navigation is not rendering links", len(visited), visited)
	}
}

// crawlableTarget normalizes a link found in rendered HTML and reports
// whether the crawl should follow it. External origins, fragments, static
// assets and binary downloads are all out of scope.
func crawlableTarget(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "mailto:") {
		return "", false
	}
	if !strings.HasPrefix(raw, "/") {
		return "", false
	}
	if idx := strings.Index(raw, "#"); idx != -1 {
		raw = raw[:idx]
	}
	if raw == "" {
		return "", false
	}
	for _, skip := range []string{"/static/", "/cli/binaries/", "/locales/", "/branding/", "/sw.js", "/manifest.json"} {
		if strings.HasPrefix(raw, skip) {
			return "", false
		}
	}
	return raw, true
}

func TestSSRFormsCarryCSRFTokenAndEnforceIt(t *testing.T) {
	res := browserRequest(t, http.MethodGet, "/", nil)
	body := make([]byte, 512*1024)
	n, _ := res.Body.Read(body)
	res.Body.Close()
	page := string(body[:n])

	mustContain(t, "index.html", page, `action="/server/preferences" method="post"`, "native theme form")
	if csrfFieldPattern.FindStringSubmatch(page) == nil {
		saveArtifact(t, "index.html", []byte(page))
		t.Fatal("theme form has no csrf_token hidden field")
	}
	var csrfCookie *http.Cookie
	for _, cookie := range res.Cookies() {
		if cookie.Name == "csrf_token" {
			csrfCookie = cookie
		}
	}
	if csrfCookie == nil {
		t.Fatal("GET / did not set a csrf_token cookie")
	}

	// A forged POST that carries neither the cookie nor the field must be
	// refused outright.
	forged := browserRequest(t, http.MethodPost, "/server/preferences", http.Header{
		"Content-Type": []string{"application/x-www-form-urlencoded"},
	})
	forged.Body.Close()
	if forged.StatusCode != http.StatusForbidden {
		t.Errorf("POST /server/preferences without a CSRF token returned %d, want 403", forged.StatusCode)
	}
}

func TestSSRPreferencesImportSetsCookiesAndRedirects(t *testing.T) {
	res := browserRequest(t, http.MethodGet, "/server/preferences/sync/import?theme=light&lang=es", nil)
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("preferences import returned %d, want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/" {
		t.Errorf("preferences import redirected to %q, want /", loc)
	}
	applied := map[string]string{}
	for _, cookie := range res.Cookies() {
		applied[cookie.Name] = cookie.Value
	}
	if applied["theme"] != "light" {
		t.Errorf("import set theme cookie to %q, want light", applied["theme"])
	}
	if applied["lang"] != "es" {
		t.Errorf("import set lang cookie to %q, want es", applied["lang"])
	}

	// An unknown value must be dropped, never applied and never a hard error.
	rejected := browserRequest(t, http.MethodGet, "/server/preferences/sync/import?theme=neon&lang=xx", nil)
	rejected.Body.Close()
	if rejected.StatusCode != http.StatusSeeOther {
		t.Fatalf("import of unknown values returned %d, want 303", rejected.StatusCode)
	}
	for _, cookie := range rejected.Cookies() {
		if cookie.Name == "theme" || cookie.Name == "lang" {
			t.Errorf("import applied unknown preference %s=%s", cookie.Name, cookie.Value)
		}
	}
}

func TestSSRRendersRequestedLanguage(t *testing.T) {
	status, body, _ := getBody(t, "/", http.Header{"Cookie": []string{"lang=es"}})
	if status != http.StatusOK {
		t.Fatalf("GET / with lang=es returned %d, want 200", status)
	}
	mustContain(t, "index-es.html", body, `<html lang="es"`, "Spanish lang attribute")
	mustContain(t, "index-es.html", body, "¿Cuál es mi dirección IP?</h1>", "Spanish landing heading")
	if strings.Contains(body, "What is my IP address?</h1>") {
		saveArtifact(t, "index-es.html", []byte(body))
		t.Error("Spanish page still renders the English heading")
	}
}

func TestSSRHealthEndpointNegotiatesJSON(t *testing.T) {
	status, body, header := getBody(t, "/server/healthz", http.Header{"Accept": []string{"application/json"}})
	if status != http.StatusOK {
		t.Fatalf("GET /server/healthz returned %d, want 200", status)
	}
	if ct := header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("health JSON Content-Type is %q", ct)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("health response is not valid JSON: %v", err)
	}
	if payload["status"] == nil {
		t.Errorf("health JSON has no status field: %v", payload)
	}
}
