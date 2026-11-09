package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/config"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/server/handler"
	"github.com/apimgr/ipgaze/src/swagger"
	"github.com/go-chi/chi/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPHandler returns the stateless MCP Streamable HTTP endpoint. The router is
// used as the dispatch target so API middleware and the existing handlers stay
// on the execution path.
func (s *Server) MCPHandler() http.Handler {
	transport := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return s.mcpServer(r)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg := config.Get(); cfg == nil || !cfg.Server.MCP.Enabled {
			lang := i18n.DetectLocale(r)
			handler.WriteAPIError(w, http.StatusNotFound, "NOT_FOUND", i18n.T(i18n.WithLang(r.Context(), lang), "errors.not_found"))
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			handler.WriteAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			return
		}
		if !s.validMCPOrigin(r) {
			handler.WriteAPIError(w, http.StatusForbidden, "FORBIDDEN", "Invalid origin")
			return
		}
		transport.ServeHTTP(w, r)
	})
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
		configured = append(configured, strings.Split(cfg.Web.CORS, ",")...)
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
	server := mcp.NewServer(&mcp.Implementation{Name: "ipgaze", Version: s.Version}, nil)
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
}

func (s *Server) registeredMCPOperations(r *http.Request) []registeredMCPOperation {
	if s.router == nil {
		return nil
	}
	baseURL := s.BaseURL
	if r != nil {
		baseURL = netutil.BuildURL(r, s.getTrust(), "")
	}
	spec := swagger.GenerateSpec(swagger.SwaggerHandlerConfig{Version: s.Version, CommitID: s.CommitID, Trust: s.getTrust()}, baseURL, "en")
	paths := make([]string, 0, len(spec.Paths))
	for path := range spec.Paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var registered []registeredMCPOperation
	for _, path := range paths {
		operations := itemOperations(spec.Paths[path])
		methods := make([]string, 0, len(operations))
		for method := range operations {
			methods = append(methods, method)
		}
		sort.Strings(methods)
		for _, method := range methods {
			operation := operations[method]
			if isVersionedAPIOperation(path) && operation != nil && operation.OperationID != "" && s.isAPIOperationRegistered(operation.OperationID, path, method) {
				registered = append(registered, registeredMCPOperation{path: path, method: method, spec: operation})
			}
		}
	}
	return registered
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
	if s.apiOperationIDs != nil {
		_, registered := s.apiOperationIDs[operationID]
		return registered
	}
	return s.hasRegisteredAPIOperation(documentedPath, documentedMethod)
}

func itemOperations(item swagger.PathItem) map[string]*swagger.Operation {
	return map[string]*swagger.Operation{
		"get": item.Get, "post": item.Post, "put": item.Put,
		"patch": item.Patch, "delete": item.Delete,
	}
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
		response = fmt.Sprintf(`{"ok":false,"error":"http_error","message":%q}`, http.StatusText(responseStatus))
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
