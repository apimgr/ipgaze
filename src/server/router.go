package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// NewChiRouter creates a new chi router instance per AI.md spec
// Uses github.com/go-chi/chi/v5 as required by PART 5
func NewChiRouter() chi.Router {
	return chi.NewRouter()
}

// appHandlerToHTTP converts an appHandler to http.HandlerFunc
// This bridges the appHandler error pattern with chi's standard handlers
func appHandlerToHTTP(h appHandler) http.HandlerFunc {
	return h.ServeHTTP
}
