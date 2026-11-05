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

	"github.com/apimgr/ipgaze/src/config"
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

func TestMCPHandlerDisabledAndMethodRules(t *testing.T) {
	path := t.TempDir() + "/server.yml"
	cfg, err := config.LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	handler := (&Server{}).MCPHandler()

	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if get.Code != http.StatusMethodNotAllowed || get.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("enabled GET: status=%d Allow=%q, want 405 and POST", get.Code, get.Header().Get("Allow"))
	}

	cfg.Server.MCP.Enabled = false
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, "/mcp", nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("disabled %s: status=%d, want 404", method, recorder.Code)
		}
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

func TestAPIV1RuntimeRegistryUsesOpenAPIRouteDefinitions(t *testing.T) {
	server := testServer()
	server.Handler()
	for _, definition := range swagger.APIV1RouteDefinitions() {
		wantRegistered := definition.OperationID != "v1_swagger" &&
			definition.OperationID != "v1_graphql_get" &&
			definition.OperationID != "v1_graphql_post"
		_, registered := server.apiOperationIDs[definition.OperationID]
		if registered != wantRegistered {
			t.Errorf("operation %q registered = %v, want %v", definition.OperationID, registered, wantRegistered)
		}
	}
	if !server.isAPIOperationRegistered("v1_ip_lookup", "/api/v1/ip/{ip}", http.MethodGet) {
		t.Fatal("registered runtime API operation was not exposed to MCP discovery")
	}
	if server.isAPIOperationRegistered("v1_graphql_get", "/api/v1/server/graphql", http.MethodGet) {
		t.Fatal("disabled GraphQL operation was exposed to MCP discovery")
	}
	for _, operationID := range []string{"v1_graphql_get", "v1_swagger"} {
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
