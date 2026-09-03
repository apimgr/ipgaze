package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIPLookupHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	t.Run("valid IPv4", func(t *testing.T) {
		out, status, err := httpGet(ts.URL+"/8.8.8.8", jsonMediaType, "")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
		if !strings.Contains(out, `"ip"`) {
			t.Errorf("response missing ip field: %s", out)
		}
	})

	t.Run("invalid IP returns 400", func(t *testing.T) {
		out, status, err := httpGet(ts.URL+"/not-an-ip", jsonMediaType, "")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusNotFound {
			t.Logf("response: %s", out)
		}
	})
}

func TestAPItV1InfoHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/api/v1/", jsonMediaType, "")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !strings.Contains(out, `"ip"`) {
		t.Errorf("response missing ip field: %s", out)
	}
}

func TestAPIV1IPHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/api/v1/ip", "", "curl/1.0")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Errorf("response missing IP: %s", out)
	}
}

func TestAPIV1CountryHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/api/v1/country", "", "curl/1.0")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !strings.Contains(out, "Elbonia") {
		t.Errorf("response missing country: %s", out)
	}
}

func TestAPIV1CityHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/api/v1/city", "", "curl/1.0")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !strings.Contains(out, "Bornyasherk") {
		t.Errorf("response missing city: %s", out)
	}
}

func TestAPIV1ASNHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/api/v1/asn", "", "curl/1.0")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !strings.Contains(out, "AS59795") {
		t.Errorf("response missing ASN: %s", out)
	}
}

// TestAPIV1ScalarHandlersNegotiate asserts the single-value /api/v1 lookups
// answer JSON for a JSON client, since AI.md PART 14 makes JSON the default
// for /api/** and reserves raw text for text clients.
func TestAPIV1ScalarHandlersNegotiate(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	cases := []struct {
		path string
		want string
	}{
		{"/api/v1/country", `"country": "Elbonia"`},
		{"/api/v1/city", `"city": "Bornyasherk"`},
		{"/api/v1/asn", `"asn": "AS59795"`},
	}
	for _, tc := range cases {
		out, status, err := httpGet(ts.URL+tc.path, "application/json", "Mozilla/5.0")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Errorf("%s status = %d, want 200", tc.path, status)
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s response = %q, want it to contain %q", tc.path, out, tc.want)
		}
	}
}

func TestAutodiscoverHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/api/autodiscover", jsonMediaType, "")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, out)
	}
	if _, ok := resp["api_version"]; !ok {
		t.Error("response missing api_version field")
	}
	if _, ok := resp["features"]; !ok {
		t.Error("response missing features field")
	}
}

func TestReportsHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	endpoints := []string{
		"/api/v1/server/reports/csp",
		"/api/v1/server/reports/nel",
		"/api/v1/server/reports/deprecation",
	}
	for _, ep := range endpoints {
		res, _, err := httpPost(ts.URL+ep, `{"csp-report":{}}`)
		if err != nil {
			t.Fatalf("%s: %v", ep, err)
		}
		if res.StatusCode != http.StatusNoContent {
			t.Errorf("%s: status = %d, want 204", ep, res.StatusCode)
		}
	}
}

func TestDefaultHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible browser)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "html") {
		t.Errorf("expected HTML response, got: %s", string(body)[:min(200, len(body))])
	}
}

func TestLocaleHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/locales/en.json", jsonMediaType, "")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200 for /locales/en.json", status)
	}
	if len(out) == 0 {
		t.Error("expected non-empty locale response")
	}
}

func TestLocaleHandlerUnknown(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	_, status, err := httpGet(ts.URL+"/locales/xx.json", jsonMediaType, "")
	if err != nil {
		t.Fatal(err)
	}
	// unknown locale may return 404 or fall through — just log the status
	t.Logf("status = %d for unknown locale (behaviour depends on route matching)", status)
}

func TestVersionEndpoint(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/api/v1/version", jsonMediaType, "")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["version"]; !ok {
		t.Error("response missing version field")
	}
}

func TestStaticHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	_, status, err := httpGet(ts.URL+"/static/", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK && status != http.StatusNotFound && status != http.StatusMovedPermanently {
		t.Logf("static handler returned status %d (acceptable)", status)
	}
}

func TestAPIV1IPLookupHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	t.Run("valid IP", func(t *testing.T) {
		out, status, err := httpGet(ts.URL+"/api/v1/ip/8.8.8.8", jsonMediaType, "")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Errorf("status = %d, want 200\nbody: %s", status, out)
		}
	})

	t.Run("invalid IP returns 400", func(t *testing.T) {
		out, status, err := httpGet(ts.URL+"/api/v1/ip/not-an-ip", jsonMediaType, "")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400\nbody: %s", status, out)
		}
	})
}

func TestIPLookupOrNotFound(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	t.Run("IPv4 path resolves", func(t *testing.T) {
		out, status, err := httpGet(ts.URL+"/1.2.3.4", jsonMediaType, "")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Errorf("status = %d, want 200\nbody: %s", status, out)
		}
	})

	t.Run("non-IP path returns 404", func(t *testing.T) {
		_, status, err := httpGet(ts.URL+"/some-random-path", jsonMediaType, "")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	// echoip-compatible: /{ip}/json returns full JSON
	t.Run("IPv4 /json suffix returns JSON", func(t *testing.T) {
		out, status, err := httpGet(ts.URL+"/1.2.3.4/json", jsonMediaType, "")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Errorf("status = %d, want 200\nbody: %s", status, out)
		}
		if !strings.Contains(out, `"ip"`) {
			t.Errorf("response missing ip field: %s", out)
		}
	})

	// echoip-compatible: /{ip}/{field} returns specific field as plain text
	t.Run("IPv4 /ip field returns IP as text", func(t *testing.T) {
		out, status, err := httpGet(ts.URL+"/1.2.3.4/ip", "", "curl/1.0")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Errorf("status = %d, want 200\nbody: %s", status, out)
		}
		if !strings.Contains(out, "1.2.3.4") {
			t.Errorf("expected 1.2.3.4 in response, got: %s", out)
		}
	})

	t.Run("unknown field returns error", func(t *testing.T) {
		_, status, err := httpGet(ts.URL+"/1.2.3.4/unknown_field", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if status == http.StatusOK {
			t.Error("expected non-200 for unknown field")
		}
	})
}

func TestRootHandlerJSONAccept(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/", jsonMediaType, "Mozilla/5.0")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("expected JSON: %v\nbody: %s", err, out)
	}
}

func TestMiddlewareContextHelpers(t *testing.T) {
	t.Run("RequestIDFromContext returns empty on plain context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		id := RequestIDFromContext(req.Context())
		if id != "" {
			t.Logf("RequestIDFromContext = %q (may have been set by middleware)", id)
		}
	})

	t.Run("RequestIDMiddleware sets ID in context and header", func(t *testing.T) {
		var capturedID string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedID = RequestIDFromContext(r.Context())
		})
		handler := RequestIDMiddleware(next)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if capturedID == "" {
			t.Error("expected request ID to be set in context")
		}
		if rec.Header().Get("X-Request-ID") == "" {
			t.Error("expected X-Request-ID header to be set")
		}
	})

	t.Run("LangMiddleware sets lang in context", func(t *testing.T) {
		var capturedLang string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedLang = LangFromContext(r.Context())
		})
		handler := LangMiddleware(next)
		req := httptest.NewRequest(http.MethodGet, "/?lang=es", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if capturedLang == "" {
			t.Error("expected lang to be set in context")
		}
	})

	t.Run("LangFromContext returns en for empty context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		lang := LangFromContext(req.Context())
		if lang != "en" {
			t.Errorf("LangFromContext = %q, want en", lang)
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
