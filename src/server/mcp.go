package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/config"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/server/handler"
	"github.com/apimgr/ipgaze/src/swagger"
	"github.com/go-chi/chi/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpProtocolVersion = "2026-07-28"

// MCPHandler returns the stateless MCP Streamable HTTP endpoint. The router is
// used as the dispatch target so API middleware and the existing handlers stay
// on the execution path.
func (s *Server) MCPHandler() http.Handler {
	transport := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return s.mcpServer(r)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.validMCPOrigin(r) {
			handler.WriteAPIError(w, http.StatusForbidden, "FORBIDDEN", handler.ErrorMessageForStatus(r, http.StatusForbidden))
			return
		}
		token := mcpBearerToken(r)
		if token == "" || !s.ValidateAPIToken(token) {
			s.auditRejectedCLIToken(r, token)
			if token != "" && s.rateLimiter != nil {
				s.rateLimiter.RecordAuthFailure(s.authClientIP(r))
			}
			s.writeMCPUnauthorized(w, r, token != "")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			handler.WriteAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", handler.ErrorMessageForStatus(r, http.StatusMethodNotAllowed))
			return
		}
		if !s.validMCPRequestHeaders(w, r) {
			return
		}
		if requiredScope := s.mcpToolRequiredScope(r); requiredScope != "" && !s.ValidateAPITokenScope(token, requiredScope) {
			s.writeMCPInsufficientScope(w, r)
			return
		}
		transport.ServeHTTP(w, r)
	})
}

func (s *Server) writeMCPInsufficientScope(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
	ctx := i18n.WithLang(r.Context(), i18n.DetectLocale(r))
	handler.WriteAPIError(w, http.StatusForbidden, "FORBIDDEN", i18n.T(ctx, "errors.forbidden"))
}

func (s *Server) writeMCPUnauthorized(w http.ResponseWriter, r *http.Request, invalid bool) {
	challenge := `Bearer realm="ipgaze"`
	ctx := i18n.WithLang(r.Context(), i18n.DetectLocale(r))
	message := i18n.T(ctx, "errors.unauthorized")
	if invalid {
		challenge += `, error="invalid_token"`
		message = i18n.T(ctx, "errors.token_invalid")
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"error": map[string]any{
			"code":    -32001,
			"message": message,
		},
	})
}

func (s *Server) validMCPRequestHeaders(w http.ResponseWriter, r *http.Request) bool {
	body, err := io.ReadAll(r.Body)
	if err == nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	var envelope struct {
		Method string `json:"method"`
		Params struct {
			ProtocolVersion string         `json:"protocolVersion"`
			Name            string         `json:"name"`
			URI             string         `json:"uri"`
			Meta            map[string]any `json:"_meta"`
		} `json:"params"`
	}
	parsed := json.Unmarshal(body, &envelope) == nil
	version := r.Header.Get("MCP-Protocol-Version")
	if version == "" && parsed && envelope.Method == "initialize" {
		version = envelope.Params.ProtocolVersion
	}
	if version == mcpProtocolVersion {
		if r.Header.Get("MCP-Protocol-Version") == "" {
			return s.writeMCPHeaderError(w, "MCP-Protocol-Version header is required", mcp.CodeHeaderMismatch, nil)
		}
	} else if version != "" {
		return s.writeMCPHeaderError(w, "unsupported protocol version", mcp.CodeUnsupportedProtocolVersion,
			mcp.UnsupportedProtocolVersionData{Supported: []string{mcpProtocolVersion}, Requested: version})
	} else {
		return s.writeMCPHeaderError(w, "MCP-Protocol-Version header is required", mcp.CodeHeaderMismatch, nil)
	}
	if !parsed {
		return true
	}
	if method := r.Header.Get("Mcp-Method"); method == "" || method != envelope.Method {
		return s.writeMCPHeaderError(w, "Mcp-Method header does not match request method", mcp.CodeHeaderMismatch, nil)
	}
	var name string
	switch envelope.Method {
	case "tools/call", "prompts/get":
		name = envelope.Params.Name
	case "resources/read":
		name = envelope.Params.URI
	}
	if name != "" || envelope.Method == "tools/call" || envelope.Method == "resources/read" || envelope.Method == "prompts/get" {
		headerName := r.Header.Get("Mcp-Name")
		if strings.HasPrefix(headerName, "=?base64?") && strings.HasSuffix(headerName, "?=") {
			encoded := strings.TrimSuffix(strings.TrimPrefix(headerName, "=?base64?"), "?=")
			decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
			if decodeErr != nil {
				return s.writeMCPHeaderError(w, "Mcp-Name header is malformed", mcp.CodeHeaderMismatch, nil)
			}
			headerName = string(decoded)
		}
		if headerName == "" || headerName != name {
			return s.writeMCPHeaderError(w, "Mcp-Name header does not match request name", mcp.CodeHeaderMismatch, nil)
		}
	}
	if bodyVersion, ok := envelope.Params.Meta["io.modelcontextprotocol/protocolVersion"].(string); ok && bodyVersion != mcpProtocolVersion {
		return s.writeMCPHeaderError(w, "MCP-Protocol-Version header does not match request metadata", mcp.CodeHeaderMismatch, nil)
	}
	return true
}

func (s *Server) writeMCPHeaderError(w http.ResponseWriter, message string, code int, data any) bool {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	response := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    any    `json:"data,omitempty"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: nil}
	response.Error.Code = code
	response.Error.Message = message
	response.Error.Data = data
	_ = json.NewEncoder(w).Encode(response)
	return false
}

func (s *Server) validMCPOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, ok := parseMCPOrigin(origin)
	if !ok {
		return false
	}
	effective, err := url.Parse(netutil.BuildURL(r, s.getTrust(), ""))
	if err == nil && sameMCPOrigin(u, effective) {
		return true
	}
	configured := []string{s.BaseURL}
	for _, domain := range strings.Split(os.Getenv("DOMAIN"), ",") {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			configured = append(configured, "https://"+domain)
		}
	}
	if cfg := config.Get(); cfg != nil {
		configured = append(configured, strings.Split(config.GetCORS(), ",")...)
	}
	for _, candidate := range configured {
		allowed, valid := parseMCPOrigin(strings.TrimSpace(candidate))
		if valid && sameMCPOrigin(u, allowed) {
			return true
		}
	}
	return false
}

func parseMCPOrigin(value string) (*url.URL, bool) {
	u, err := url.Parse(value)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" ||
		(u.Scheme != "http" && u.Scheme != "https") || u.Path != "" ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, false
	}
	return u, true
}

func sameMCPOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, b.Scheme) ||
		!strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return port(a) == port(b)
}

func (s *Server) mcpServer(r *http.Request) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "ipgaze", Version: s.Version}, &mcp.ServerOptions{
		SupportedProtocolVersions: []string{mcpProtocolVersion},
	})
	if s.router == nil {
		return server
	}
	for _, operation := range s.registeredMCPOperations(r) {
		tool := mcpToolSpec(operation.path, operation.method, operation.spec)
		toolPath := operation.path
		toolMethod := strings.ToUpper(operation.method)
		toolSpec := operation.spec
		server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return s.dispatchMCPTool(ctx, r, req, toolMethod, toolPath, toolSpec)
		})
	}
	return server
}

type registeredMCPOperation struct {
	path   string
	method string
	spec   *swagger.Operation
	route  swagger.Route
}

func (s *Server) registeredMCPOperations(r *http.Request) []registeredMCPOperation {
	if s.router == nil {
		return nil
	}
	routes := s.RegisteredAPIRoutes()
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	var registered []registeredMCPOperation
	for _, route := range routes {
		path, method := route.Path, route.Method
		if !isVersionedAPIOperation(path) || route.Handler == nil || route.Internal || route.OperationID == "v1Mcp" {
			continue
		}
		if !s.isAPIOperationRegistered(route.OperationID, path, method) || !s.mcpOperationVisible(r, path, route) {
			continue
		}
		operation := swagger.OperationForRoute(route, "en")
		if operation != nil {
			registered = append(registered, registeredMCPOperation{path: path, method: method, spec: operation, route: route})
		}
	}
	return registered
}

func (s *Server) mcpOperationVisible(r *http.Request, path string, route swagger.Route) bool {
	if route.Internal || route.Auth == "service" {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/server/preferences/tokens") {
		return false
	}
	switch route.Auth {
	case "none":
		return r != nil && s.mcpTokenAuthorized(mcpBearerToken(r), mcpOperationRequiredScope(path, route.Method, route.Auth))
	case "operator":
		return r != nil && s.ValidateOperatorToken(mcpBearerToken(r))
	case "token", "owner":
		return r != nil && s.mcpTokenAuthorized(mcpBearerToken(r), mcpOperationRequiredScope(path, route.Method, route.Auth))
	}
	return false
}

func (s *Server) mcpTokenAuthorized(token, requiredScope string) bool {
	return s.ValidateAPITokenScope(token, requiredScope) || s.ValidateOperatorToken(token)
}

func mcpOperationRequiredScope(path, method, auth string) string {
	if strings.HasPrefix(path, "/api/v1/server/preferences/tokens") {
		return handler.OwnerTokenScopeGlobal
	}
	if auth == "operator" {
		return handler.OwnerTokenScopeGlobal
	}
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return handler.OwnerTokenScopeRead
	default:
		return handler.OwnerTokenScopeReadWrite
	}
}

func (s *Server) mcpToolRequiredScope(r *http.Request) string {
	if r == nil || s.router == nil {
		return ""
	}
	var request struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if json.Unmarshal(body, &request) != nil || request.Method != "tools/call" || request.Params.Name == "" {
		return ""
	}
	for _, route := range s.RegisteredAPIRoutes() {
		if route.Handler == nil || !isVersionedAPIOperation(route.Path) || route.OperationID == "v1Mcp" {
			continue
		}
		operation := swagger.OperationForRoute(route, "en")
		if operation == nil || mcpToolSpec(route.Path, route.Method, operation).Name != request.Params.Name {
			continue
		}
		return mcpOperationRequiredScope(route.Path, route.Method, route.Auth)
	}
	return ""
}

func mcpBearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func (s *Server) registeredMCPTools(r *http.Request) []handler.MCPToolDescription {
	operations := s.registeredMCPOperations(r)
	tools := make([]handler.MCPToolDescription, 0, len(operations))
	for _, operation := range operations {
		tool := mcpToolSpec(operation.path, operation.method, operation.spec)
		tools = append(tools, handler.MCPToolDescription{Name: tool.Name, Description: tool.Description})
	}
	return tools
}

func (s *Server) hasRegisteredAPIOperation(documentedPath, documentedMethod string) bool {
	if s.router == nil {
		return false
	}
	samplePath := regexp.MustCompile(`\{[^/{}]+\}`).ReplaceAllString(documentedPath, "mcp-value")
	samplePath = strings.TrimSuffix(samplePath, "/")
	registered := false
	_ = chi.Walk(s.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !strings.EqualFold(method, documentedMethod) {
			return nil
		}
		route = strings.TrimSuffix(route, "/")
		pattern := strings.Builder{}
		pattern.WriteByte('^')
		for i := 0; i < len(route); i++ {
			switch route[i] {
			case '*':
				pattern.WriteString(".*")
			case '{':
				for i < len(route) && route[i] != '}' {
					i++
				}
				pattern.WriteString("[^/]+")
			default:
				pattern.WriteString(regexp.QuoteMeta(string(route[i])))
			}
		}
		pattern.WriteByte('$')
		re, err := regexp.Compile(pattern.String())
		if err == nil && re.MatchString(samplePath) {
			registered = true
		}
		return nil
	})
	return registered
}

func (s *Server) isAPIOperationRegistered(operationID, documentedPath, documentedMethod string) bool {
	if route, ok := swagger.RouteForOperationID(operationID); ok {
		operationID = route.OperationID
	}
	if s.apiOperationIDs != nil {
		_, registered := s.apiOperationIDs[operationID]
		return registered
	}
	return s.hasRegisteredAPIOperation(documentedPath, documentedMethod)
}

func isVersionedAPIOperation(path string) bool {
	return path == "/api/v1" || strings.HasPrefix(path, "/api/v1/")
}

func mcpToolSpec(path, method string, op *swagger.Operation) *mcp.Tool {
	name := op.OperationID
	if name == "" {
		name = strings.Trim(strings.ToLower(method)+"_"+path, "/")
		name = strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_").Replace(name)
	}
	props := make(map[string]any)
	var required []string
	for _, p := range op.Parameters {
		var schema any = map[string]any{"type": "string"}
		if p.Schema != nil {
			schema = p.Schema
		}
		props[p.Name] = schema
		if p.Required {
			required = append(required, p.Name)
		}
	}
	if op.RequestBody != nil {
		bodySchema := any(map[string]any{"type": "object"})
		for _, media := range op.RequestBody.Content {
			if media.Schema != nil {
				bodySchema = media.Schema
				break
			}
		}
		props["body"] = bodySchema
		if op.RequestBody.Required {
			required = append(required, "body")
		}
	}
	input := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		sort.Strings(required)
		input["required"] = required
	}
	encoded, _ := json.Marshal(input)
	return &mcp.Tool{Name: name, Description: op.Description, InputSchema: json.RawMessage(encoded)}
}

func (s *Server) dispatchMCPTool(ctx context.Context, origin *http.Request, req *mcp.CallToolRequest, method, path string, op *swagger.Operation) (*mcp.CallToolResult, error) {
	route := path
	status := http.StatusInternalServerError
	defer func() {
		s.auditMCPToolCall(origin, req, method, route, status)
	}()

	var args map[string]json.RawMessage
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		status = http.StatusBadRequest
		return nil, fmt.Errorf("invalid tool arguments: %w", err)
	}
	for _, p := range op.Parameters {
		if p.In != "path" {
			continue
		}
		value, ok := args[p.Name]
		if !ok {
			if p.Required {
				status = http.StatusBadRequest
				return nil, fmt.Errorf("missing required path parameter %q", p.Name)
			}
			continue
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			var scalar any
			if err := json.Unmarshal(value, &scalar); err != nil {
				status = http.StatusBadRequest
				return nil, fmt.Errorf("path parameter %q must be a string or number", p.Name)
			}
			switch scalar.(type) {
			case float64:
				text = string(value)
			default:
				status = http.StatusBadRequest
				return nil, fmt.Errorf("path parameter %q must be a string or number", p.Name)
			}
		}
		path = strings.ReplaceAll(path, "{"+p.Name+"}", text)
	}
	query := url.Values{}
	for _, p := range op.Parameters {
		if p.In != "query" {
			continue
		}
		if value, ok := args[p.Name]; ok {
			var text string
			if err := json.Unmarshal(value, &text); err == nil {
				query.Set(p.Name, text)
			} else {
				query.Set(p.Name, string(value))
			}
		}
	}
	var body io.Reader
	if raw, ok := args["body"]; ok {
		body = bytes.NewReader(raw)
	}
	apiPath := path
	request := origin.Clone(ctx)
	request.Method = method
	request.URL.Path = apiPath
	request.URL.RawPath = ""
	request.URL.RawQuery = query.Encode()
	request.RequestURI = ""
	request.Header = origin.Header.Clone()
	request.Header.Del("Cookie")
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if body != nil {
		request.Body = io.NopCloser(body)
	} else {
		request.Body = http.NoBody
	}
	recorder := newResponseRecorder()
	s.router.ServeHTTP(recorder, request)
	responseStatus := recorder.status
	if responseStatus == 0 {
		responseStatus = http.StatusOK
	}
	status = responseStatus
	response := recorder.body.String()
	if response == "" && responseStatus >= http.StatusBadRequest {
		response = fmt.Sprintf(`{"ok":false,"error":"http_error","message":%q}`, handler.ErrorMessageForStatus(origin, responseStatus))
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: response}},
		IsError: responseStatus >= http.StatusBadRequest,
	}, nil
}

func (s *Server) auditMCPToolCall(origin *http.Request, req *mcp.CallToolRequest, method, route string, status int) {
	if s.logManager == nil {
		return
	}
	var ip string
	if origin != nil {
		if clientIP, err := s.RequestIP(origin, false); err == nil {
			ip = clientIP.String()
		}
	}
	tool := ""
	if req != nil && req.Params != nil {
		tool = req.Params.Name
	}
	result, severity := "success", "info"
	if status >= http.StatusBadRequest {
		result, severity = "failure", "warn"
	}
	s.logManager.WriteAudit(applog.AuditEvent{
		Event:    "api.request",
		Source:   "mcp",
		Category: "api",
		Severity: severity,
		Actor:    applog.AuditActor{IP: ip},
		Details: map[string]any{
			"tool":   tool,
			"method": method,
			"route":  route,
			"status": status,
		},
		Result: result,
	})
}

type responseRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: make(http.Header)}
}

func (w *responseRecorder) Header() http.Header { return w.header }
func (w *responseRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *responseRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(b)
}
