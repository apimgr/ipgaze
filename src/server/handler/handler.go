// Package handler contains HTTP handlers organized by domain.
// Per AI.md PART 14: all responses use JSON envelopes with data/error structure.
package handler

import (
	"encoding/json"
	"net/http"
)

// APIResponse is the canonical JSON envelope for all API responses per AI.md PART 9 and PART 14.
// Success:    {"ok": true, "data": ...}
// Paginated:  {"ok": true, "data": [...], "pagination": {"page","limit","total","pages"}}
// Error:      {"ok": false, "error": "ERROR_CODE", "message": "...", "details": {...}}
type APIResponse struct {
	// OK discriminates success (true) from failure (false).
	OK bool `json:"ok"`
	// Data is present on success; omitted on error.
	Data interface{} `json:"data,omitempty"`
	// Pagination carries list pagination metadata on success per AI.md PART 14.
	Pagination *APIPagination `json:"pagination,omitempty"`
	// Error is the UPPER_SNAKE_CASE error code on failure; omitted on success.
	Error string `json:"error,omitempty"`
	// Message is the human-readable error description on failure; omitted on success.
	Message string `json:"message,omitempty"`
	// Details carries additional structured error context on failure; omitted on success.
	Details interface{} `json:"details,omitempty"`
}

// APIPagination carries list pagination metadata per AI.md PART 14 (default limit 250).
type APIPagination struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
	Total int `json:"total"`
	Pages int `json:"pages"`
}

// SendAPIResponseOK writes a 200 JSON success envelope to w.
func SendAPIResponseOK(w http.ResponseWriter, data interface{}, pagination *APIPagination) {
	sendAPIResponse(w, http.StatusOK, &APIResponse{OK: true, Data: data, Pagination: pagination})
}

// SendAPIResponseError writes a JSON error envelope with the given status code,
// UPPER_SNAKE_CASE error code, human-readable message, and optional structured
// details, per AI.md PART 14's canonical error shape.
func SendAPIResponseError(w http.ResponseWriter, status int, code, message string, details interface{}) {
	sendAPIResponse(w, status, &APIResponse{OK: false, Error: code, Message: message, Details: details})
}

// sendAPIResponse marshals resp as 2-space-indented JSON and writes it with the given status code.
// Per AI.md PART 14: all JSON responses use json.MarshalIndent with 2-space indentation + trailing newline.
func sendAPIResponse(w http.ResponseWriter, status int, resp *APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		// Fallback: write a minimal error body; headers already sent so status is fixed.
		w.Write([]byte("{\n  \"ok\": false,\n  \"error\": \"INTERNAL_ERROR\",\n  \"message\": \"failed to encode response\"\n}\n")) //nolint:errcheck
		return
	}
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}
