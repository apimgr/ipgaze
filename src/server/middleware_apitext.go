package server

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// APITextSuffixMiddleware implements content-negotiation priority 1 of AI.md
// PART 14: a `.txt` extension on ANY `/api/{api_version}/*` route forces plain
// text, always. It strips the suffix before routing so a single handler
// registration serves both forms, and pins Accept to text/plain so every
// downstream handler negotiates text without needing its own suffix check.
func APITextSuffixMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routePath := r.URL.Path
		rctx := chi.RouteContext(r.Context())
		if rctx != nil && rctx.RoutePath != "" {
			routePath = rctx.RoutePath
		}
		if !strings.HasSuffix(routePath, ".txt") {
			next.ServeHTTP(w, r)
			return
		}
		trimmed := strings.TrimSuffix(routePath, ".txt")
		if trimmed == "" {
			trimmed = "/"
		}
		if rctx != nil {
			rctx.RoutePath = trimmed
		}
		outbound := r.Clone(r.Context())
		outbound.URL.Path = strings.TrimSuffix(outbound.URL.Path, ".txt")
		if outbound.URL.RawPath != "" {
			outbound.URL.RawPath = strings.TrimSuffix(outbound.URL.RawPath, ".txt")
		}
		outbound.Header.Set("Accept", "text/plain")
		next.ServeHTTP(w, outbound)
	})
}
