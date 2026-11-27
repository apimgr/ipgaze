package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apimgr/ipgaze/src/swagger"
)

type orderedTextResponse struct {
	First  string `json:"first"`
	Second string `json:"second"`
}

func TestRouteTextSerializerPreservesBareJSONContracts(t *testing.T) {
	const body = `{"data":{"status":"ok"}}`
	handler := withRouteTextSerializer(swaggerRoute("healthz", ""), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/server/healthz", nil)
	request.Header.Set("Accept", "text/plain")
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Header().Get("Content-Type") != "application/json" || response.Body.String() != body {
		t.Fatalf("bare JSON response changed: content-type=%q body=%q", response.Header().Get("Content-Type"), response.Body.String())
	}
}

func TestRouteTextSerializerUsesPrimaryAndResponseOrder(t *testing.T) {
	t.Run("primary scalar", func(t *testing.T) {
		route := swaggerRoute("country", "country")
		handler := withRouteTextSerializer(route, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"country":"US"}`))
		})
		request := httptest.NewRequest(http.MethodGet, "/api/v1/country", nil)
		request.Header.Set("Accept", "text/plain")
		response := httptest.NewRecorder()
		handler(response, request)
		if got := response.Body.String(); got != "US\n" {
			t.Fatalf("primary text = %q, want US", got)
		}
	})

	t.Run("response struct field order", func(t *testing.T) {
		route := swaggerRoute("ordered", "")
		route.Response = orderedTextResponse{}
		handler := withRouteTextSerializer(route, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"data":{"first":"one","second":"two"}}`))
		})
		request := httptest.NewRequest(http.MethodGet, "/api/v1/ordered", nil)
		request.Header.Set("Accept", "text/plain")
		response := httptest.NewRecorder()
		handler(response, request)
		want := "OK: Retrieved successfully\nfirst: one\nsecond: two\n"
		if got := response.Body.String(); got != want {
			t.Fatalf("ordered text = %q, want %q", got, want)
		}
	})
}

func TestRouteTextSerializerLeavesBinaryResponseUntouched(t *testing.T) {
	route := swaggerRoute("binary", "")
	route.Binary = "image/png"
	handler := withRouteTextSerializer(route, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", route.Binary)
		_, _ = w.Write([]byte("png-bytes"))
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/binary", nil)
	request.Header.Set("Accept", "text/plain")
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Header().Get("Content-Type") != "image/png" || response.Body.String() != "png-bytes" {
		t.Fatalf("binary response changed: content-type=%q body=%q", response.Header().Get("Content-Type"), response.Body.String())
	}
}

func swaggerRoute(operationID, primary string) swagger.Route {
	return swagger.Route{OperationID: operationID, Primary: primary, Message: "Retrieved successfully"}
}
