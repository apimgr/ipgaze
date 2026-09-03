package graphql

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGraphQLJSONIsTwoSpaceIndented asserts the 2-space indentation AI.md
// PART 14 requires of every JSON response, for both the success and the
// rejection path.
func TestGraphQLJSONIsTwoSpaceIndented(t *testing.T) {
	setResolverDeps(t, Deps{Health: fakeHealth})
	ensureSchema(t)

	cases := []struct {
		name string
		body string
	}{
		{"success", `{"query":"{ health { status } }"}`},
		{"error", `not json at all`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			handleGraphQLQuery(w, r)

			out := w.Body.String()
			if !strings.Contains(out, "\n  \"") {
				t.Errorf("response is not 2-space indented:\n%s", out)
			}
			if strings.Contains(out, "\t") {
				t.Errorf("response contains a tab, want spaces:\n%s", out)
			}
		})
	}
}
