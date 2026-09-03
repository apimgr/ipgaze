package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/tor"
	"github.com/go-chi/chi/v5"
)

// stubTorController is an in-memory TorController used to exercise the
// loopback gate and the method check without a real Tor process.
type stubTorController struct {
	restarts     int
	regenerated  string
	applied      string
	imported     string
	vanityStart  string
	vanityBusy   bool
	vanityStops  int
	vanityActive bool
}

func (s *stubTorController) IsAvailable() bool { return true }
func (s *stubTorController) IsRunning() bool   { return true }
func (s *stubTorController) GetInfo() tor.Info {
	return tor.Info{Enabled: true, Running: true, Status: "running", Hostname: "stub.onion"}
}
func (s *stubTorController) GetHostname() string { return "stub.onion" }
func (s *stubTorController) BackendPort() int    { return 9061 }
func (s *stubTorController) TorrcPath() string   { return "/config/tor/torrc" }
func (s *stubTorController) SiteDir() string     { return "/data/tor/site" }
func (s *stubTorController) Validate() error     { return nil }
func (s *stubTorController) Restart() error      { s.restarts++; return nil }
func (s *stubTorController) RegenerateAddress() (string, error) {
	s.regenerated = "regenerated.onion"
	return s.regenerated, nil
}
func (s *stubTorController) StartVanitySearch(prefix string, _ int) error {
	if s.vanityBusy {
		return fmt.Errorf("%w for prefix %q", tor.ErrVanitySearchRunning, s.vanityStart)
	}
	s.vanityStart = prefix
	return nil
}
func (s *stubTorController) StopVanitySearch() bool {
	s.vanityStops++
	return s.vanityActive
}
func (s *stubTorController) VanitySearchStatus() tor.VanityStatus {
	return tor.VanityStatus{State: tor.VanityStateIdle}
}
func (s *stubTorController) ApplyVanityAddress(address string) (string, error) {
	s.applied = address
	return "applied.onion", nil
}
func (s *stubTorController) ImportKeys(srcDir string) (string, error) {
	s.imported = srcDir
	return "imported.onion", nil
}

// newTorControlTestRouter mounts only the Tor control routes on a bare chi
// router so the gate can be tested without the full server wiring.
func newTorControlTestRouter(tc TorController) http.Handler {
	s := &Server{TorControl: tc}
	r := chi.NewRouter()
	s.registerTorControlRoutes(r)
	return r
}

// torControlRequestFor builds a request to path from remoteAddr.
func torControlRequestFor(method, path, remoteAddr, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	return req
}

func TestTorControlLoopbackGateRejectsRemote(t *testing.T) {
	router := newTorControlTestRouter(&stubTorController{})

	remotes := []string{"203.0.113.9:51000", "10.1.2.3:44444", "[2001:db8::1]:8443", "192.168.1.5:1234"}
	paths := map[string]string{
		"/server/tor/status":       http.MethodGet,
		"/server/tor/validate":     http.MethodPost,
		"/server/tor/restart":      http.MethodPost,
		"/server/tor/regenerate":   http.MethodPost,
		"/server/tor/vanity/start": http.MethodPost,
		"/server/tor/vanity/stop":  http.MethodPost,
		"/server/tor/vanity/apply": http.MethodPost,
		"/server/tor/import-keys":  http.MethodPost,
	}
	for path, method := range paths {
		for _, remote := range remotes {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, torControlRequestFor(method, path, remote, "{}"))
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s from %s = %d, want 404", method, path, remote, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "tor") {
				t.Errorf("%s %s from %s leaked route details: %s", method, path, remote, rec.Body.String())
			}
		}
	}
}

func TestTorControlLoopbackGateIgnoresProxyHeaders(t *testing.T) {
	router := newTorControlTestRouter(&stubTorController{})

	// A remote caller cannot spoof loopback with a forwarding header.
	req := torControlRequestFor(http.MethodGet, "/server/tor/status", "198.51.100.7:6000", "")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("spoofed X-Forwarded-For got %d, want 404", rec.Code)
	}

	// A loopback caller is not blocked by a hostile forwarding header either.
	req = torControlRequestFor(http.MethodGet, "/server/tor/status", "127.0.0.1:5555", "")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback request with X-Forwarded-For got %d, want 200", rec.Code)
	}
}

func TestTorControlAcceptsLoopback(t *testing.T) {
	stub := &stubTorController{}
	router := newTorControlTestRouter(stub)

	for _, remote := range []string{"127.0.0.1:5555", "127.0.0.53:40000", "[::1]:5555"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, torControlRequestFor(http.MethodGet, "/server/tor/status", remote, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /server/tor/status from %s = %d, want 200", remote, rec.Code)
		}
		var resp struct {
			OK   bool `json:"ok"`
			Data struct {
				Running     bool   `json:"running"`
				Hostname    string `json:"hostname"`
				BackendPort int    `json:"backend_port"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode status body: %v", err)
		}
		if !resp.OK || !resp.Data.Running || resp.Data.Hostname != "stub.onion" || resp.Data.BackendPort != 9061 {
			t.Fatalf("unexpected status payload: %s", rec.Body.String())
		}
	}
}

func TestTorControlWrongMethod(t *testing.T) {
	router := newTorControlTestRouter(&stubTorController{})

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/server/tor/status"},
		{http.MethodGet, "/server/tor/restart"},
		{http.MethodGet, "/server/tor/regenerate"},
		{http.MethodDelete, "/server/tor/validate"},
		{http.MethodPut, "/server/tor/vanity/start"},
		{http.MethodGet, "/server/tor/vanity/stop"},
		{http.MethodGet, "/server/tor/vanity/apply"},
		{http.MethodGet, "/server/tor/import-keys"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, torControlRequestFor(c.method, c.path, "127.0.0.1:5555", ""))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", c.method, c.path, rec.Code)
		}
	}
}

func TestTorControlWithoutControllerIsNotFound(t *testing.T) {
	s := &Server{}
	r := chi.NewRouter()
	s.registerTorControlRoutes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, torControlRequestFor(http.MethodGet, "/server/tor/status", "127.0.0.1:5555", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status with no controller = %d, want 404", rec.Code)
	}
}

func TestTorControlActionsReachController(t *testing.T) {
	stub := &stubTorController{}
	router := newTorControlTestRouter(stub)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, torControlRequestFor(http.MethodPost, "/server/tor/restart", "127.0.0.1:5555", ""))
	if rec.Code != http.StatusOK || stub.restarts != 1 {
		t.Fatalf("restart: code=%d restarts=%d", rec.Code, stub.restarts)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, torControlRequestFor(http.MethodPost, "/server/tor/vanity/start", "127.0.0.1:5555", `{"prefix":"Abc","workers":2}`))
	if rec.Code != http.StatusOK || stub.vanityStart != "abc" {
		t.Fatalf("vanity start: code=%d prefix=%q", rec.Code, stub.vanityStart)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, torControlRequestFor(http.MethodPost, "/server/tor/import-keys", "127.0.0.1:5555", `{"path":"/keys"}`))
	if rec.Code != http.StatusOK || stub.imported != "/keys" {
		t.Fatalf("import-keys: code=%d path=%q", rec.Code, stub.imported)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, torControlRequestFor(http.MethodPost, "/server/tor/import-keys", "127.0.0.1:5555", `{}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import-keys with no path = %d, want 400", rec.Code)
	}
}

func TestTorVanityStopHandler(t *testing.T) {
	stub := &stubTorController{vanityActive: true}
	router := newTorControlTestRouter(stub)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, torControlRequestFor(http.MethodPost, "/server/tor/vanity/stop", "127.0.0.1:5555", ""))
	if rec.Code != http.StatusOK || stub.vanityStops != 1 {
		t.Fatalf("vanity stop: code=%d stops=%d", rec.Code, stub.vanityStops)
	}
	if !strings.Contains(rec.Body.String(), "vanity search cancelled") {
		t.Fatalf("vanity stop body = %s, want the cancelled message", rec.Body.String())
	}

	// Stopping with nothing running is a no-op, not an error.
	stub.vanityActive = false
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, torControlRequestFor(http.MethodPost, "/server/tor/vanity/stop", "127.0.0.1:5555", ""))
	if rec.Code != http.StatusOK || stub.vanityStops != 2 {
		t.Fatalf("idle vanity stop: code=%d stops=%d", rec.Code, stub.vanityStops)
	}
	if !strings.Contains(rec.Body.String(), "no vanity search is running") {
		t.Fatalf("idle vanity stop body = %s, want the no-op message", rec.Body.String())
	}
}

func TestTorVanityStartConflict(t *testing.T) {
	stub := &stubTorController{vanityBusy: true, vanityStart: "abc"}
	router := newTorControlTestRouter(stub)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, torControlRequestFor(http.MethodPost, "/server/tor/vanity/start", "127.0.0.1:5555", `{"prefix":"xyz"}`))
	if rec.Code != http.StatusConflict {
		t.Fatalf("second vanity start = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `abc`) {
		t.Fatalf("conflict body = %s, want the running prefix", rec.Body.String())
	}
}
