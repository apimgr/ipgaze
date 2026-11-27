package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/swagger"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPOriginParsingAndComparison(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "https origin", value: "https://example.com", valid: true},
		{name: "http origin", value: "http://example.com:80", valid: true},
		{name: "path rejected", value: "https://example.com/path", valid: false},
		{name: "query rejected", value: "https://example.com?x=1", valid: false},
		{name: "userinfo rejected", value: "https://user@example.com", valid: false},
		{name: "opaque rejected", value: "https:opaque", valid: false},
		{name: "invalid scheme", value: "ftp://example.com", valid: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin, valid := parseMCPOrigin(tt.value)
			if valid != tt.valid {
				t.Fatalf("parseMCPOrigin(%q) valid = %v, want %v", tt.value, valid, tt.valid)
			}
			if valid && origin == nil {
				t.Fatal("valid origin parsed as nil")
			}
		})
	}
	httpsOrigin, _ := parseMCPOrigin("https://example.com")
	httpsDefaultPort, _ := parseMCPOrigin("https://EXAMPLE.com:443")
	httpOrigin, _ := parseMCPOrigin("http://example.com")
	if !sameMCPOrigin(httpsOrigin, httpsDefaultPort) {
		t.Fatal("default HTTPS port should match explicit port 443")
	}
	if sameMCPOrigin(httpsOrigin, httpOrigin) {
		t.Fatal("different schemes must not be treated as the same origin")
	}
}

func TestValidMCPOrigin(t *testing.T) {
	server := &Server{BaseURL: "https://public.example"}
	request := httptest.NewRequest(http.MethodPost, "https://public.example/mcp", nil)
	request.Host = "internal.example"
	request.Header.Set("Origin", "https://public.example")
	if !server.validMCPOrigin(request) {
		t.Fatal("configured base URL origin should be accepted")
	}
	request.Header.Set("Origin", "http://public.example")
	if server.validMCPOrigin(request) {
		t.Fatal("origin with a different scheme should be rejected")
	}
	request.Header.Set("Origin", "not an origin")
	if server.validMCPOrigin(request) {
		t.Fatal("malformed origin should be rejected")
	}
	request.Header.Del("Origin")
	if !server.validMCPOrigin(request) {
		t.Fatal("requests without Origin should be accepted")
	}
}

func TestMCPHandlerMethodRules(t *testing.T) {
	server := &Server{}
	server.SetOperatorToken("adm_test_mcp_method_token")
	handler := server.MCPHandler()

	get := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer adm_test_mcp_method_token")
	handler.ServeHTTP(get, request)
	if get.Code != http.StatusMethodNotAllowed || get.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("enabled GET: status=%d Allow=%q, want 405 and POST", get.Code, get.Header().Get("Allow"))
	}

}

func TestMCPHandlerRequiresOnlyConfiguredProtocolRevision(t *testing.T) {
	server := &Server{}
	server.SetOperatorToken("adm_test_mcp_operator_token")
	handler := server.MCPHandler()
	for _, test := range []struct {
		name    string
		version string
		code    int
	}{
		{name: "missing version", code: mcp.CodeHeaderMismatch},
		{name: "older version", version: "2025-03-26", code: mcp.CodeUnsupportedProtocolVersion},
		{name: "future version", version: "2099-01-01", code: mcp.CodeUnsupportedProtocolVersion},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			request.Header.Set("Authorization", "Bearer adm_test_mcp_operator_token")
			if test.version != "" {
				request.Header.Set("MCP-Protocol-Version", test.version)
			}
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Header().Get("Content-Type"), "application/json") {
				t.Fatalf("status/content-type = %d/%q, want 400/application/json", recorder.Code, recorder.Header().Get("Content-Type"))
			}
			var response struct {
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode JSON-RPC response: %v", err)
			}
			if response.Error.Code != test.code {
				t.Errorf("error code = %d, want %d", response.Error.Code, test.code)
			}
		})
	}
}

func TestMCPHandlerValidatesRequiredMetadataHeaders(t *testing.T) {
	server := &Server{}
	server.SetOperatorToken("adm_test_mcp_operator_token")
	handler := server.MCPHandler()
	tests := []struct {
		name       string
		body       string
		method     string
		toolName   string
		wantStatus int
		wantCode   int
	}{
		{name: "method missing", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, wantStatus: http.StatusBadRequest, wantCode: mcp.CodeHeaderMismatch},
		{name: "method mismatch", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, method: "tools/call", wantStatus: http.StatusBadRequest, wantCode: mcp.CodeHeaderMismatch},
		{name: "tool name mismatch", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_ip"}}`, method: "tools/call", toolName: "lookup_other", wantStatus: http.StatusBadRequest, wantCode: mcp.CodeHeaderMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer adm_test_mcp_operator_token")
			request.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
			if test.method != "" {
				request.Header.Set("Mcp-Method", test.method)
			}
			if test.toolName != "" {
				request.Header.Set("Mcp-Name", test.toolName)
			}
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			var response struct {
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if response.Error.Code != test.wantCode {
				t.Errorf("error code = %d, want %d", response.Error.Code, test.wantCode)
			}
		})
	}

	oldInitialize := httptest.NewRecorder()
	oldRequest := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`))
	oldRequest.Header.Set("Authorization", "Bearer adm_test_mcp_operator_token")
	handler.ServeHTTP(oldInitialize, oldRequest)
	if oldInitialize.Code != http.StatusBadRequest || !strings.Contains(oldInitialize.Body.String(), `"code":-32022`) {
		t.Errorf("old initialize response = %d %s, want unsupported protocol error", oldInitialize.Code, oldInitialize.Body.String())
	}
}

func TestMCPHandlerRequiresValidBearerToken(t *testing.T) {
	server := &Server{}
	server.SetOperatorToken("adm_test_mcp_operator_token")
	handler := server.MCPHandler()
	for _, test := range []struct {
		name  string
		token string
	}{
		{name: "missing"},
		{name: "invalid", token: "Bearer own_00000000000000000000000000000000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			request.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
			if test.token != "" {
				request.Header.Set("Authorization", test.token)
			}
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") == "" {
				t.Fatalf("response = %d %q %s, want 401 with WWW-Authenticate", recorder.Code, recorder.Header().Get("WWW-Authenticate"), recorder.Body.String())
			}
		})
	}
}

func TestMCPToolSpecUsesOperationIDAndOpenAPISchema(t *testing.T) {
	operation := &swagger.Operation{
		OperationID: "lookup_ip",
		Description: "Look up an IP address.",
		Parameters: []swagger.Parameter{{
			Name: "ip", In: "path", Required: true, Schema: &swagger.Schema{Type: "string"},
		}},
	}
	tool := mcpToolSpec("/api/v1/ip/{ip}", "get", operation)
	if tool.Name != "lookup_ip" || tool.Description != operation.Description {
		t.Fatalf("tool metadata = (%q, %q), want operationId and description", tool.Name, tool.Description)
	}
	encodedSchema, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatalf("encode input schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(encodedSchema, &schema); err != nil {
		t.Fatalf("decode input schema: %v", err)
	}
	properties := schema["properties"].(map[string]any)
	if properties["ip"] == nil {
		t.Fatalf("path parameter missing from schema: %#v", schema)
	}
	if !isVersionedAPIOperation("/api/v1/server/about") || isVersionedAPIOperation("/server/about") || isVersionedAPIOperation("/api/autodiscover") {
		t.Fatal("versioned API operation filter accepted the wrong paths")
	}
}

func TestMCPOperationVisibilityFollowsBearerSecurityAndExcludesTokenManagement(t *testing.T) {
	server := &Server{}
	server.SetOperatorToken("adm_test_operator_token")
	public, _ := swagger.RouteForOperationID("v1_ip")
	protected, _ := swagger.RouteForOperationID("v1_auth_check")
	internal := swagger.Route{Auth: "none", Listed: true, Internal: true}
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	if !server.mcpOperationVisible(request, "/api/v1/ip", public) {
		t.Fatal("public operation should be visible without a token")
	}
	if server.mcpOperationVisible(request, "/api/v1/internal", internal) {
		t.Fatal("internal operation must never be visible in MCP")
	}
	if server.mcpOperationVisible(request, "/api/v1/server/auth/check", protected) {
		t.Fatal("operator-only operation should be hidden from anonymous callers")
	}
	request.Header.Set("Authorization", "Bearer wrong-token")
	if server.mcpOperationVisible(request, "/api/v1/server/auth/check", protected) {
		t.Fatal("operator-only operation should be hidden for an invalid bearer token")
	}
	request.Header.Set("Authorization", "Bearer adm_test_operator_token")
	if !server.mcpOperationVisible(request, "/api/v1/server/auth/check", protected) {
		t.Fatal("operator-only operation should be visible to the operator")
	}
	if server.mcpOperationVisible(request, "/api/v1/server/preferences/tokens", public) {
		t.Fatal("token-management operations must never be exposed as MCP tools")
	}
}

func TestMCPToolInventoryRequiresRegisteredRuntimeRoute(t *testing.T) {
	server := &Server{router: NewChiRouter()}
	server.router.Get("/api/v1/ip/*", func(http.ResponseWriter, *http.Request) {})
	if !server.hasRegisteredAPIOperation("/api/v1/ip/{ip}", http.MethodGet) {
		t.Fatal("registered wildcard route was not matched to its OpenAPI operation")
	}
	if server.hasRegisteredAPIOperation("/api/v1/server/about", http.MethodGet) {
		t.Fatal("unregistered OpenAPI operation was included in the MCP inventory")
	}
	if server.hasRegisteredAPIOperation("/api/v1/ip/{ip}", http.MethodPost) {
		t.Fatal("registered operation matched the wrong HTTP method")
	}
}

func TestMCPIncludesAuthorizedUnlistedRoutes(t *testing.T) {
	server := testServer()
	server.SetOperatorToken("adm_test_operator_token")
	server.Handler()
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	for _, operation := range server.registeredMCPOperations(request) {
		if operation.route.OperationID == "v1AuthCheck" {
			t.Fatal("operator-only tool was visible without operator authorization")
		}
	}
	request.Header.Set("Authorization", "Bearer adm_test_operator_token")
	for _, operation := range server.registeredMCPOperations(request) {
		if operation.route.OperationID == "v1AuthCheck" {
			return
		}
	}
	t.Fatal("MCP omitted an authorized operator route because it was not Listed")
}

func TestAPIV1RuntimeRegistryUsesOpenAPIRouteDefinitions(t *testing.T) {
	server := testServer()
	server.Handler()
	routes := server.RegisteredAPIRoutes()
	if len(routes) == 0 {
		t.Fatal("runtime route registry is empty")
	}
	for _, route := range routes {
		if !strings.HasPrefix(route.Path, "/api/v1") {
			continue
		}
		if route.Handler == nil {
			t.Errorf("registered route %q has no mounted handler", route.OperationID)
		}
		if _, ok := server.apiOperationIDs[route.OperationID]; !ok {
			t.Errorf("route %q is absent from the runtime operation set", route.OperationID)
		}
		if route.Internal {
			t.Errorf("internal route %q entered the public API registry", route.OperationID)
		}
	}
	if !server.isAPIOperationRegistered("v1IpLookup", "/api/v1/ip/{ip}", http.MethodGet) {
		t.Fatal("registered runtime API operation was not exposed to MCP discovery")
	}
	if server.isAPIOperationRegistered("v1GraphQLGet", "/api/v1/server/graphql", http.MethodGet) {
		t.Fatal("disabled GraphQL operation was exposed to MCP discovery")
	}
	for _, operationID := range []string{"v1GraphQLGet", "v1Swagger"} {
		if _, ok := server.apiOperationIDs[operationID]; ok {
			t.Errorf("disabled optional operation %q present in runtime registry", operationID)
		}
	}
}

func TestDispatchMCPToolPreservesAPIRequestContextAndMapsErrors(t *testing.T) {
	server := &Server{router: NewChiRouter()}
	server.router.Post("/api/v1/resources/{id}", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer caller-token" || r.Header.Get("Cookie") != "" {
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		if r.RemoteAddr != "192.0.2.8:3210" {
			http.Error(w, "peer not preserved", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"id":"` + r.PathValue("id") + `","query":"` + r.URL.Query().Get("q") + `","body":` + string(body) + `}`))
	})
	server.router.Get("/api/v1/denied", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"ok":false,"error":"UNAUTHORIZED","message":"unauthorized"}`, http.StatusUnauthorized)
	})

	origin := httptest.NewRequest(http.MethodPost, "https://public.example/mcp", nil)
	origin.RemoteAddr = "192.0.2.8:3210"
	origin.Header.Set("Authorization", "Bearer caller-token")
	origin.Header.Set("Cookie", "ipgaze_owner_token=ambient-secret")
	request := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{"id":123,"q":"find","body":{"active":true}}`)},
		Extra:  &mcp.RequestExtra{Header: origin.Header},
	}
	operation := &swagger.Operation{
		Parameters: []swagger.Parameter{
			{Name: "id", In: "path", Required: true, Schema: &swagger.Schema{Type: "integer"}},
			{Name: "q", In: "query", Schema: &swagger.Schema{Type: "string"}},
		},
		RequestBody: &swagger.RequestBody{Required: true},
	}
	result, err := server.dispatchMCPTool(context.Background(), origin, request, http.MethodPost, "/api/v1/resources/{id}", operation)
	if err != nil {
		t.Fatalf("dispatch MCP tool: %v", err)
	}
	if result.IsError {
		t.Fatalf("successful API response was marked as error: %+v", result)
	}
	content := result.Content[0].(*mcp.TextContent)
	if !strings.Contains(content.Text, `"ok":true`) || !strings.Contains(content.Text, `"query":"find"`) {
		t.Fatalf("API response not preserved in tool result: %s", content.Text)
	}

	denied := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{}`)}}
	errorResult, err := server.dispatchMCPTool(context.Background(), origin, denied, http.MethodGet, "/api/v1/denied", &swagger.Operation{})
	if err != nil {
		t.Fatalf("dispatch denied tool: %v", err)
	}
	if !errorResult.IsError || !strings.Contains(errorResult.Content[0].(*mcp.TextContent).Text, "UNAUTHORIZED") {
		t.Fatalf("API error was not exposed as an error tool result: %+v", errorResult)
	}

	malformed := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage("{")}}
	if _, err := server.dispatchMCPTool(context.Background(), origin, malformed, http.MethodGet, "/api/v1/denied", &swagger.Operation{}); err == nil {
		t.Fatal("malformed tool arguments should return an error")
	}
	missingPath := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{}`)}}
	if _, err := server.dispatchMCPTool(context.Background(), origin, missingPath, http.MethodGet, "/api/v1/resources/{id}", &swagger.Operation{Parameters: []swagger.Parameter{{Name: "id", In: "path", Required: true}}}); err == nil {
		t.Fatal("missing required path parameter should return an error")
	}
}

func TestAuditMCPToolCallLabelsSource(t *testing.T) {
	logDir := t.TempDir()
	manager, err := applog.NewManager(logDir, applog.DefaultConfig())
	if err != nil {
		t.Fatalf("create log manager: %v", err)
	}
	server := &Server{logManager: manager}
	origin := httptest.NewRequest(http.MethodPost, "https://public.example/mcp", nil)
	origin.RemoteAddr = "192.0.2.8:3210"
	request := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "lookup_ip"}}
	server.auditMCPToolCall(origin, request, http.MethodGet, "/api/v1/ip/{ip}", http.StatusOK)
	manager.Close()

	data, err := os.ReadFile(filepath.Join(logDir, "audit.log"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var event applog.AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &event); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	if event.Source != "mcp" || event.Event != "api.request" || event.Actor.IP != "192.0.2.8" {
		t.Errorf("audit event source/event/actor = %q/%q/%q", event.Source, event.Event, event.Actor.IP)
	}
	if event.Details["tool"] != "lookup_ip" || event.Details["route"] != "/api/v1/ip/{ip}" {
		t.Errorf("audit event details = %#v", event.Details)
	}
}
