package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/server/handler"
	"github.com/apimgr/ipgaze/src/tor"
)

// torControlMaxBody caps the request body the Tor control endpoints will read.
// The payloads are a prefix, an address, or a filesystem path — never large.
const torControlMaxBody = 8 << 10

// TorController is the subset of *tor.TorManager the internal control channel
// drives. The server holds the live manager that owns the embedded Tor
// process, so `{project_name} tor ...` reaches Tor only through these methods
// (AI.md PART 31.1 "CLI-to-running-server control channel").
type TorController interface {
	IsAvailable() bool
	IsRunning() bool
	GetInfo() tor.Info
	GetHostname() string
	BackendPort() int
	TorrcPath() string
	SiteDir() string
	Validate() error
	Restart() error
	RegenerateAddress() (string, error)
	StartVanitySearch(prefix string, workers int) error
	StopVanitySearch() bool
	VanitySearchStatus() tor.VanityStatus
	ApplyVanityAddress(address string) (string, error)
	ImportKeys(srcDir string) (string, error)
}

// SetTorControl attaches the live Tor manager (or a test stub) so the
// internal /server/tor/* control endpoints can drive it.
func (s *Server) SetTorControl(tc TorController) {
	s.TorControl = tc
}

// torControlRequest is the shared body shape for the mutating control
// endpoints. Every field is optional; each endpoint reads only what it needs.
type torControlRequest struct {
	// Prefix is the desired address prefix for /server/tor/vanity/start.
	Prefix string `json:"prefix,omitempty"`
	// Workers is the vanity search worker count; 0 means logical CPUs − 1
	// (minimum 1).
	Workers int `json:"workers,omitempty"`
	// Address selects which found candidate /server/tor/vanity/apply installs.
	Address string `json:"address,omitempty"`
	// Path is the source directory for /server/tor/import-keys.
	Path string `json:"path,omitempty"`
}

// torStatusResponse is the payload of GET /server/tor/status.
type torStatusResponse struct {
	Enabled     bool             `json:"enabled"`
	Running     bool             `json:"running"`
	Status      string           `json:"status"`
	Hostname    string           `json:"hostname,omitempty"`
	BackendPort int              `json:"backend_port,omitempty"`
	TorrcPath   string           `json:"torrc_path"`
	SiteDir     string           `json:"site_dir"`
	Vanity      tor.VanityStatus `json:"vanity"`
}

// torActionResponse is the payload of the mutating control endpoints.
type torActionResponse struct {
	Action   string `json:"action"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	Hostname string `json:"hostname,omitempty"`
	Message  string `json:"message,omitempty"`
}

// torValidateResponse is the payload of POST /server/tor/validate.
type torValidateResponse struct {
	Valid     bool   `json:"valid"`
	TorrcPath string `json:"torrc_path"`
	SiteDir   string `json:"site_dir"`
	Problem   string `json:"problem,omitempty"`
}

// torControlRoute pairs a control endpoint with the single HTTP method it
// accepts.
type torControlRoute struct {
	method string
	fn     func(http.ResponseWriter, *http.Request, TorController)
}

// registerTorControlRoutes wires the INTERNAL Tor control channel described in
// AI.md PART 31.1. These routes are the same tier as /server/metrics: never
// documented in OpenAPI, never advertised under /.well-known or FeaturesInfo,
// and never reachable through /api/{api_version}/**. Each path accepts every
// HTTP method at the router level so that a wrong method still passes through
// the loopback gate first — chi's own 405 would otherwise reveal the route to
// a remote caller.
func (s *Server) registerTorControlRoutes(r interface {
	Handle(pattern string, h http.Handler)
}) {
	routes := map[string]torControlRoute{
		"/server/tor/status":       {http.MethodGet, torStatusHandler},
		"/server/tor/validate":     {http.MethodPost, torValidateHandler},
		"/server/tor/restart":      {http.MethodPost, torRestartHandler},
		"/server/tor/regenerate":   {http.MethodPost, torRegenerateHandler},
		"/server/tor/vanity/start": {http.MethodPost, torVanityStartHandler},
		"/server/tor/vanity/stop":  {http.MethodPost, torVanityStopHandler},
		"/server/tor/vanity/apply": {http.MethodPost, torVanityApplyHandler},
		"/server/tor/import-keys":  {http.MethodPost, torImportKeysHandler},
	}
	for pattern, route := range routes {
		r.Handle(pattern, s.torControlEndpoint(route.method, route.fn))
	}
}

// torControlEndpoint applies the loopback gate and the method check shared by
// every Tor control endpoint, then dispatches to fn with the live controller.
func (s *Server) torControlEndpoint(method string, fn func(http.ResponseWriter, *http.Request, TorController)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Loopback gate (AI.md PART 31.1): only the immediate TCP peer counts.
		// X-Forwarded-For and every other proxy header are ignored outright,
		// and a non-loopback caller gets 404 rather than 403 so the endpoint
		// stays undiscoverable.
		if !handler.IsLoopbackRequest(r) {
			torControlNotFound(w, r)
			return
		}
		if r.Method != method {
			handler.SendAPIResponseError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
				i18n.T(r.Context(), "errors.method_not_allowed"), nil)
			return
		}
		if s.TorControl == nil {
			// No Tor manager attached — the control channel does not exist on
			// this server, so it answers exactly as an unknown path would.
			torControlNotFound(w, r)
			return
		}
		fn(w, r, s.TorControl)
	})
}

// torControlNotFound writes the same generic 404 an unknown path produces.
func torControlNotFound(w http.ResponseWriter, r *http.Request) {
	handler.SendAPIResponseError(w, http.StatusNotFound, "NOT_FOUND",
		i18n.T(r.Context(), "errors.not_found"), nil)
}

// decodeTorControlRequest reads the optional JSON body of a control request.
// An empty body is valid and yields a zero-valued request.
func decodeTorControlRequest(r *http.Request) (torControlRequest, error) {
	var req torControlRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, torControlMaxBody))
	if err != nil {
		return req, err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return req, nil
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, err
	}
	return req, nil
}

// torControlBadRequest reports a malformed or rejected control request,
// keeping the specific reason in details for the local CLI caller.
func torControlBadRequest(w http.ResponseWriter, r *http.Request, reason string) {
	handler.SendAPIResponseError(w, http.StatusBadRequest, "BAD_REQUEST",
		i18n.T(r.Context(), "errors.bad_request"), map[string]string{"reason": reason})
}

// torControlFailed reports a control operation that could not be completed,
// keeping the specific reason in details for the local CLI caller.
func torControlFailed(w http.ResponseWriter, r *http.Request, reason string) {
	handler.SendAPIResponseError(w, http.StatusInternalServerError, "SERVER_ERROR",
		i18n.T(r.Context(), "errors.server_error"), map[string]string{"reason": reason})
}

// torStatusHandler serves GET /server/tor/status.
func torStatusHandler(w http.ResponseWriter, _ *http.Request, tc TorController) {
	info := tc.GetInfo()
	handler.SendAPIResponseOK(w, torStatusResponse{
		Enabled:     info.Enabled,
		Running:     info.Running,
		Status:      info.Status,
		Hostname:    info.Hostname,
		BackendPort: tc.BackendPort(),
		TorrcPath:   tc.TorrcPath(),
		SiteDir:     tc.SiteDir(),
		Vanity:      tc.VanitySearchStatus(),
	}, nil)
}

// torValidateHandler serves POST /server/tor/validate.
func torValidateHandler(w http.ResponseWriter, _ *http.Request, tc TorController) {
	resp := torValidateResponse{
		Valid:     true,
		TorrcPath: tc.TorrcPath(),
		SiteDir:   tc.SiteDir(),
	}
	if err := tc.Validate(); err != nil {
		resp.Valid = false
		resp.Problem = err.Error()
	}
	handler.SendAPIResponseOK(w, resp, nil)
}

// torRestartHandler serves POST /server/tor/restart.
func torRestartHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	if !tc.IsAvailable() {
		torControlFailed(w, r, "tor binary not found")
		return
	}
	if err := tc.Restart(); err != nil {
		torControlFailed(w, r, err.Error())
		return
	}
	torActionOK(w, "restart", tc, "")
}

// torRegenerateHandler serves POST /server/tor/regenerate.
func torRegenerateHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	if !tc.IsAvailable() {
		torControlFailed(w, r, "tor binary not found")
		return
	}
	address, err := tc.RegenerateAddress()
	if err != nil {
		torControlFailed(w, r, err.Error())
		return
	}
	handler.SendAPIResponseOK(w, torActionResponse{
		Action:   "regenerate",
		Running:  tc.IsRunning(),
		Status:   tc.GetInfo().Status,
		Hostname: address,
	}, nil)
}

// torVanityStartHandler serves POST /server/tor/vanity/start.
func torVanityStartHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	req, err := decodeTorControlRequest(r)
	if err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	if err := tc.StartVanitySearch(strings.ToLower(strings.TrimSpace(req.Prefix)), req.Workers); err != nil {
		// One search at a time (AI.md PART 31.1): a second start is a
		// conflict, not a malformed request.
		if errors.Is(err, tor.ErrVanitySearchRunning) {
			handler.SendAPIResponseError(w, http.StatusConflict, "CONFLICT",
				i18n.T(r.Context(), "errors.conflict"), map[string]string{"reason": err.Error()})
			return
		}
		torControlBadRequest(w, r, err.Error())
		return
	}
	handler.SendAPIResponseOK(w, torActionResponse{
		Action:  "vanity/start",
		Running: tc.IsRunning(),
		Status:  tc.GetInfo().Status,
		Message: "vanity search started",
	}, nil)
}

// torVanityStopHandler serves POST /server/tor/vanity/stop. Stopping when no
// search is running is a no-op, not an error (AI.md PART 31.1).
func torVanityStopHandler(w http.ResponseWriter, _ *http.Request, tc TorController) {
	message := "no vanity search is running"
	if tc.StopVanitySearch() {
		message = "vanity search cancelled"
	}
	handler.SendAPIResponseOK(w, torActionResponse{
		Action:  "vanity/stop",
		Running: tc.IsRunning(),
		Status:  tc.GetInfo().Status,
		Message: message,
	}, nil)
}

// torVanityApplyHandler serves POST /server/tor/vanity/apply.
func torVanityApplyHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	req, err := decodeTorControlRequest(r)
	if err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	address, err := tc.ApplyVanityAddress(strings.ToLower(strings.TrimSpace(req.Address)))
	if err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	handler.SendAPIResponseOK(w, torActionResponse{
		Action:   "vanity/apply",
		Running:  tc.IsRunning(),
		Status:   tc.GetInfo().Status,
		Hostname: address,
	}, nil)
}

// torImportKeysHandler serves POST /server/tor/import-keys.
func torImportKeysHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	req, err := decodeTorControlRequest(r)
	if err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	path := strings.TrimSpace(req.Path)
	if path == "" {
		torControlBadRequest(w, r, "import path must not be empty")
		return
	}
	address, err := tc.ImportKeys(path)
	if err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	handler.SendAPIResponseOK(w, torActionResponse{
		Action:   "import-keys",
		Running:  tc.IsRunning(),
		Status:   tc.GetInfo().Status,
		Hostname: address,
	}, nil)
}

// torActionOK writes the standard success payload for a control action.
func torActionOK(w http.ResponseWriter, action string, tc TorController, message string) {
	handler.SendAPIResponseOK(w, torActionResponse{
		Action:   action,
		Running:  tc.IsRunning(),
		Status:   tc.GetInfo().Status,
		Hostname: tc.GetHostname(),
		Message:  message,
	}, nil)
}
