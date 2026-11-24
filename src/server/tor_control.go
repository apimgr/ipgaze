package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
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
	GetControlStatus() tor.ControlStatus
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
	// Confirm must be true for destructive address or key replacement actions.
	Confirm bool `json:"confirm,omitempty"`
}

// torStatusResponse is the payload of GET /server/tor/status.
type torStatusResponse struct {
	Running            bool             `json:"running"`
	PID                *int             `json:"pid,omitempty"`
	Version            string           `json:"version"`
	OnionAddress       string           `json:"onion_address,omitempty"`
	BootstrapPercent   int              `json:"bootstrap_percent"`
	CircuitEstablished bool             `json:"circuit_established"`
	Vanity             tor.VanityStatus `json:"vanity"`
}

// torActionResponse is the payload of the mutating control endpoints.
type torActionResponse struct {
	Restarted       bool     `json:"restarted,omitempty"`
	OnionAddress    string   `json:"onion_address,omitempty"`
	PreviousAddress string   `json:"previous_address,omitempty"`
	State           string   `json:"state,omitempty"`
	Prefix          string   `json:"prefix,omitempty"`
	Workers         int      `json:"workers,omitempty"`
	Stopped         bool     `json:"stopped"`
	Candidates      []string `json:"candidates"`
}

// torValidateResponse is the payload of POST /server/tor/validate.
type torValidateResponse struct {
	Valid  bool               `json:"valid"`
	Errors []torValidateError `json:"errors"`
}

type torValidateError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
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
			torControlNotFound(w, r)
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
	body, err := io.ReadAll(io.LimitReader(r.Body, torControlMaxBody+1))
	if err != nil {
		return req, err
	}
	if len(body) > torControlMaxBody {
		return req, errors.New("request body is too large")
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return req, nil
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if mediaType != "application/json" {
		return req, errors.New("Content-Type must be application/json")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return req, errors.New("request body must contain one JSON object")
	}
	return req, nil
}

func torControlConfirmationRequired(w http.ResponseWriter, r *http.Request) {
	handler.SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED",
		i18n.T(r.Context(), "errors.required"), map[string]string{"field": "confirm"})
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
	runtimeStatus := tc.GetControlStatus()
	var pid *int
	if runtimeStatus.PID > 0 {
		pid = &runtimeStatus.PID
	}
	handler.SendAPIResponseOK(w, torStatusResponse{
		Running: info.Running, PID: pid, Version: runtimeStatus.Version,
		OnionAddress: info.Hostname, BootstrapPercent: runtimeStatus.BootstrapPercent,
		CircuitEstablished: runtimeStatus.CircuitEstablished, Vanity: tc.VanitySearchStatus(),
	}, nil)
}

// torValidateHandler serves POST /server/tor/validate.
func torValidateHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	if err := rejectTorControlBody(r); err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	resp := torValidateResponse{Valid: true, Errors: []torValidateError{}}
	if err := tc.Validate(); err != nil {
		resp.Valid = false
		resp.Errors = append(resp.Errors, torValidateError{Field: "torrc", Message: err.Error()})
	}
	handler.SendAPIResponseOK(w, resp, nil)
}

// torRestartHandler serves POST /server/tor/restart.
func torRestartHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	if err := rejectTorControlBody(r); err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	if !tc.IsAvailable() {
		torControlFailed(w, r, "tor binary not found")
		return
	}
	if err := tc.Restart(); err != nil {
		torControlFailed(w, r, err.Error())
		return
	}
	handler.SendAPIResponseOK(w, torActionResponse{Restarted: true, OnionAddress: tc.GetHostname()}, nil)
}

// rejectTorControlBody enforces endpoint contracts whose request body is
// explicitly `none` in AI.md PART 31.1.
func rejectTorControlBody(r *http.Request) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, torControlMaxBody+1))
	if err != nil {
		return err
	}
	if len(body) > torControlMaxBody {
		return errors.New("request body is too large")
	}
	if len(strings.TrimSpace(string(body))) != 0 {
		return errors.New("request body is not allowed")
	}
	return nil
}

// torRegenerateHandler serves POST /server/tor/regenerate.
func torRegenerateHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	req, err := decodeTorControlRequest(r)
	if err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	if !req.Confirm {
		torControlConfirmationRequired(w, r)
		return
	}
	if !tc.IsAvailable() {
		torControlFailed(w, r, "tor binary not found")
		return
	}
	previousAddress := tc.GetHostname()
	address, err := tc.RegenerateAddress()
	if err != nil {
		torControlFailed(w, r, err.Error())
		return
	}
	handler.SendAPIResponseOK(w, torActionResponse{OnionAddress: address, PreviousAddress: previousAddress}, nil)
}

// torVanityStartHandler serves POST /server/tor/vanity/start.
func torVanityStartHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	req, err := decodeTorControlRequest(r)
	if err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	prefix := strings.TrimSpace(req.Prefix)
	if err := tor.ValidateVanityPrefix(prefix); err != nil {
		handler.SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED", i18n.T(r.Context(), "errors.bad_request"), map[string]string{"field": "prefix", "reason": err.Error()})
		return
	}
	if err := tc.StartVanitySearch(prefix, req.Workers); err != nil {
		// One search at a time (AI.md PART 31.1): a second start is a
		// conflict, not a malformed request.
		if errors.Is(err, tor.ErrVanitySearchRunning) {
			handler.SendAPIResponseError(w, http.StatusConflict, "CONFLICT",
				i18n.T(r.Context(), "errors.conflict"), map[string]string{"prefix": tc.VanitySearchStatus().Prefix})
			return
		}
		handler.SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED", i18n.T(r.Context(), "errors.bad_request"), map[string]string{"field": "prefix", "reason": err.Error()})
		return
	}
	status := tc.VanitySearchStatus()
	handler.SendAPIResponseAccepted(w, torActionResponse{State: "running", Prefix: status.Prefix, Workers: status.Workers})
}

// torVanityStopHandler serves POST /server/tor/vanity/stop. Stopping when no
// search is running is a no-op, not an error (AI.md PART 31.1).
func torVanityStopHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	if err := rejectTorControlBody(r); err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	stopped := tc.StopVanitySearch()
	candidates := tc.VanitySearchStatus().Candidates
	if candidates == nil {
		candidates = []string{}
	}
	handler.SendAPIResponseOK(w, torActionResponse{Stopped: stopped, Candidates: candidates}, nil)
}

// torVanityApplyHandler serves POST /server/tor/vanity/apply.
func torVanityApplyHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	req, err := decodeTorControlRequest(r)
	if err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	if !req.Confirm {
		torControlConfirmationRequired(w, r)
		return
	}
	address, err := tc.ApplyVanityAddress(strings.TrimSpace(req.Address))
	if err != nil {
		if strings.Contains(err.Error(), "multiple vanity candidates") || strings.Contains(err.Error(), "matches multiple vanity candidates") {
			var candidates []string
			for _, candidate := range tc.VanitySearchStatus().Candidates {
				if req.Address == "" || strings.HasPrefix(candidate, strings.TrimSpace(req.Address)) {
					candidates = append(candidates, candidate)
				}
			}
			handler.SendAPIResponseError(w, http.StatusConflict, "CONFLICT", i18n.T(r.Context(), "errors.conflict"), map[string]any{"candidates": candidates})
			return
		}
		if strings.Contains(err.Error(), "no vanity candidates") || strings.Contains(err.Error(), "no vanity candidate matches") || (strings.Contains(err.Error(), "candidate") && strings.Contains(err.Error(), "not found")) {
			handler.SendAPIResponseError(w, http.StatusNotFound, "NOT_FOUND", i18n.T(r.Context(), "errors.not_found"), nil)
			return
		}
		torControlFailed(w, r, err.Error())
		return
	}
	handler.SendAPIResponseOK(w, torActionResponse{OnionAddress: address}, nil)
}

// torImportKeysHandler serves POST /server/tor/import-keys.
func torImportKeysHandler(w http.ResponseWriter, r *http.Request, tc TorController) {
	req, err := decodeTorControlRequest(r)
	if err != nil {
		torControlBadRequest(w, r, err.Error())
		return
	}
	if !req.Confirm {
		torControlConfirmationRequired(w, r)
		return
	}
	path := strings.TrimSpace(req.Path)
	if path == "" || !filepath.IsAbs(path) {
		handler.SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED", i18n.T(r.Context(), "errors.bad_request"), map[string]string{"field": "path", "reason": "import path must be absolute"})
		return
	}
	address, err := tc.ImportKeys(path)
	if err != nil {
		handler.SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED", i18n.T(r.Context(), "errors.bad_request"), map[string]string{"field": "path", "reason": err.Error()})
		return
	}
	handler.SendAPIResponseOK(w, torActionResponse{OnionAddress: address}, nil)
}
