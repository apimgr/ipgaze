package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPStatusToErrorCode(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{http.StatusBadRequest, "BAD_REQUEST"},
		{http.StatusUnauthorized, "UNAUTHORIZED"},
		{http.StatusForbidden, "FORBIDDEN"},
		{http.StatusNotFound, "NOT_FOUND"},
		{http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED"},
		{http.StatusConflict, "CONFLICT"},
		{http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY"},
		{http.StatusTooManyRequests, "RATE_LIMITED"},
		{http.StatusInternalServerError, "SERVER_ERROR"},
		{http.StatusBadGateway, "BAD_GATEWAY"},
		{http.StatusServiceUnavailable, "MAINTENANCE"},
		{http.StatusTeapot, "SERVER_ERROR"},
		{599, "SERVER_ERROR"},
	}
	for _, tt := range tests {
		got := httpStatusToErrorCode(tt.code)
		if got != tt.want {
			t.Errorf("httpStatusToErrorCode(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestInternalServerError(t *testing.T) {
	err := internalServerError(fmt.Errorf("boom"))
	if err.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want %d", err.Code, http.StatusInternalServerError)
	}
	if err.Error == nil {
		t.Error("expected non-nil error")
	}
}

func TestAppErrorHelpers(t *testing.T) {
	t.Run("notFound", func(t *testing.T) {
		e := notFound(fmt.Errorf("not found"))
		if e.Code != http.StatusNotFound {
			t.Errorf("code = %d, want %d", e.Code, http.StatusNotFound)
		}
	})

	t.Run("badRequest", func(t *testing.T) {
		e := badRequest(fmt.Errorf("bad"))
		if e.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want %d", e.Code, http.StatusBadRequest)
		}
	})

	t.Run("AsJSON sets content type", func(t *testing.T) {
		e := badRequest(fmt.Errorf("bad")).AsJSON()
		if !e.IsJSON() {
			t.Error("expected IsJSON() to be true after AsJSON()")
		}
		if e.ContentType != jsonMediaType {
			t.Errorf("ContentType = %q, want %q", e.ContentType, jsonMediaType)
		}
	})

	t.Run("WithMessage sets message", func(t *testing.T) {
		msg := "custom error message"
		e := badRequest(fmt.Errorf("bad")).WithMessage(msg)
		if e.Message != msg {
			t.Errorf("Message = %q, want %q", e.Message, msg)
		}
	})
}

func TestAppErrorServeHTTP_JSON(t *testing.T) {
	handler := appHandler(func(w http.ResponseWriter, r *http.Request) *appError {
		return badRequest(fmt.Errorf("invalid input")).
			WithMessage("Invalid request format").
			AsJSON()
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"BAD_REQUEST"`) {
		t.Errorf("body missing error code: %s", body)
	}
	if !strings.Contains(body, `"Invalid request format"`) {
		t.Errorf("body missing message: %s", body)
	}
}

func TestAppErrorServeHTTP_DefaultMessages(t *testing.T) {
	codes := []struct {
		code    int
		factory func(error) *appError
	}{
		{http.StatusNotFound, notFound},
		{http.StatusBadRequest, badRequest},
		{http.StatusInternalServerError, internalServerError},
	}
	for _, tc := range codes {
		handler := appHandler(func(w http.ResponseWriter, r *http.Request) *appError {
			return tc.factory(fmt.Errorf("err"))
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Errorf("code %d: got status %d", tc.code, rec.Code)
		}
	}
}

func TestAppErrorServeHTTP_NoError(t *testing.T) {
	handler := appHandler(func(w http.ResponseWriter, r *http.Request) *appError {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestNotFoundHandler(t *testing.T) {
	t.Run("plain text accept", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/missing", nil)
		rec := httptest.NewRecorder()
		appHandler(NotFoundHandler).ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("json accept", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/missing", nil)
		req.Header.Set("accept", jsonMediaType)
		rec := httptest.NewRecorder()
		appHandler(NotFoundHandler).ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"NOT_FOUND"`) {
			t.Errorf("body missing NOT_FOUND error code: %s", body)
		}
	})

	t.Run("api path defaults to json with no accept header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/nonexistent", nil)
		req.Header.Set("User-Agent", "python-requests/2.31.0")
		rec := httptest.NewRecorder()
		appHandler(NotFoundHandler).ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"NOT_FOUND"`) {
			t.Errorf("api path with non-tool UA should default to JSON, got: %s", body)
		}
	})

	t.Run("api path with curl UA stays text", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/nonexistent", nil)
		req.Header.Set("User-Agent", "curl/8.4.0")
		rec := httptest.NewRecorder()
		appHandler(NotFoundHandler).ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, `"NOT_FOUND"`) {
			t.Errorf("api path with curl UA should stay plain text, got: %s", body)
		}
	})

	t.Run("api path with .txt suffix stays text", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/nonexistent.txt", nil)
		req.Header.Set("Accept", jsonMediaType)
		rec := httptest.NewRecorder()
		appHandler(NotFoundHandler).ServeHTTP(rec, req)
		body := rec.Body.String()
		if strings.Contains(body, `"NOT_FOUND"`) {
			t.Errorf(".txt suffix should always win to plain text, got: %s", body)
		}
	})
}
