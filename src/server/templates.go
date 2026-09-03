package server

import (
	"embed"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/common/theme"
	"github.com/apimgr/ipgaze/src/server/handler"
	"github.com/yuin/goldmark"
)

//go:embed all:template
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// templateFuncMap returns the template.FuncMap exposing the "t"/"tf"/"tp"
// translation helpers (per AI.md PART 30), the "themeCSS" helper (per
// AI.md PART 16 "Themes (NON-NEGOTIABLE)"), and the "asset" cache-busting
// helper (per AI.md PART 9 "Asset Version-Busting (REQUIRED)") to all page
// and layout templates. Templates call the translation helpers with a
// locale string (e.g. .Lang) rather than a context.Context.
//
// assetStamp is the running build's {project_version}-{short_commit} stamp
// (see Server.AssetStamp); every hand-written "/static/..." URL in a
// template must instead go through {{ asset "/static/..." }} so a stale
// browser cache never survives a deploy.
func templateFuncMap(assetStamp string) template.FuncMap {
	return template.FuncMap{
		"t": func(lang, key string) string {
			return i18n.Translate(lang, key)
		},
		"tf": func(lang, key string, args ...string) string {
			return i18n.TranslateFormat(lang, key, args...)
		},
		"tp": func(lang, key string, count int) string {
			return i18n.TranslatePlural(lang, key, count)
		},
		// nextTheme renders the theme toggle's POST target as the next mode
		// after the one actually in effect for this request (AI.md PART 16
		// "Theme Toggle" -> "Theme Cycle Logic"). A hardcoded target would
		// only ever switch the theme once and then resubmit the same value.
		"nextTheme": handler.NextTheme,
		// themeCSS renders the unified color palette (src/common/theme) as
		// CSS custom properties for inline injection in base.tmpl, so the
		// web UI, Swagger, and GraphQL all consume the exact same Dracula
		// (dark) / GitHub Light (light) values instead of duplicating
		// hardcoded hex literals.
		"themeCSS": func() template.CSS {
			return template.CSS(theme.CSSVariables())
		},
		// themeColor resolves the <meta name="theme-color"> value from the
		// same src/common/theme palette the stylesheet variables come from,
		// so the browser chrome tint tracks the theme actually in effect
		// instead of a hardcoded literal (AI.md PART 16 "Themes
		// (NON-NEGOTIABLE)": never hardcode colors).
		"themeColor": func(name string) string {
			return theme.Palette(theme.Name(name)).Background
		},
		// asset appends the build stamp as a "?v=" query param (or "&v=" if
		// the path already has a query string) so the static handler can
		// tell a current-release request from a stale one (AI.md PART 9).
		"asset": func(path string) string {
			if assetStamp == "" {
				return path
			}
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			return path + sep + "v=" + assetStamp
		},
		// markdownToHTML renders operator-supplied Markdown content blocks
		// (server.privacy.content.*) to sanitized HTML for privacy.tmpl
		// (AI.md PART 16 "/server/privacy"). goldmark's default renderer
		// HTML-escapes raw HTML in the source by default, so this is safe
		// against operator-authored config content.
		"markdownToHTML": func(src string) template.HTML {
			var buf strings.Builder
			if err := goldmark.Convert([]byte(src), &buf); err != nil {
				return template.HTML(template.HTMLEscapeString(src))
			}
			return template.HTML(buf.String())
		},
		// humanize converts a snake_case identifier (e.g. a
		// SharingCondition.Condition value like "user_initiated") into a
		// human-readable, title-cased label ("User Initiated") for
		// privacy.tmpl's "Data Storage & Third-Party Sharing" section
		// (AI.md PART 16 "/server/privacy").
		"humanize": func(s string) string {
			words := strings.Split(strings.ReplaceAll(s, "_", " "), " ")
			for i, w := range words {
				if w == "" {
					continue
				}
				words[i] = strings.ToUpper(w[:1]) + w[1:]
			}
			return strings.Join(words, " ")
		},
	}
}

// InitTemplates validates that the embedded template FS is parseable.
// Per AI.md PART 16: All template files MUST use .tmpl extension.
// The result is discarded here; NewPageRenderer() creates per-request trees.
func InitTemplates() error {
	_, err := template.New("").Funcs(templateFuncMap("")).ParseFS(templateFS,
		"template/*.tmpl",
		"template/*/*.tmpl",
		"template/*/*/*.tmpl",
	)
	return err
}

// PageRenderer renders a named page template into w using the shared layout.
// The page argument is the filename (e.g. "about.tmpl") under template/page/.
// This avoids duplicate {{define}} conflicts when all page templates share the
// same "title" and "content" block names.
type PageRenderer func(w http.ResponseWriter, r *http.Request, page string, data interface{}) error

// buildBaseTemplate parses the shared layout+partials template set. Both
// NewPageRenderer (200 OK pages) and NewTemplateExecutor (the buffered,
// status-agnostic executor used by error.go's themed error-page path) clone
// this same base so the two never duplicate the ParseFS() call list.
func buildBaseTemplate(assetStamp string) *template.Template {
	return template.Must(template.New("").Funcs(templateFuncMap(assetStamp)).ParseFS(templateFS,
		"template/layout/base.tmpl",
		"template/partial/head.tmpl",
		"template/partial/scripts.tmpl",
		"template/partial/public/header.tmpl",
		"template/partial/public/nav.tmpl",
		"template/partial/public/footer.tmpl",
		"template/partial/error.tmpl",
		"template/partial/announcement_banner.tmpl",
		"template/partial/consent_banner.tmpl",
	))
}

// NewPageRenderer returns a PageRenderer backed by the embedded template FS.
// Each call clones the layout+partials base and then parses only the requested
// page template on top, so per-page {{define "title"}} and {{define "content"}}
// blocks never conflict with one another. assetStamp is threaded into the
// "asset" template helper (AI.md PART 9 "Asset Version-Busting").
func NewPageRenderer(assetStamp string) PageRenderer {
	base := buildBaseTemplate(assetStamp)
	return func(w http.ResponseWriter, r *http.Request, page string, data interface{}) error {
		t, err := base.Clone()
		if err != nil {
			return err
		}
		t, err = t.ParseFS(templateFS, "template/page/"+page)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// HTML documents are always fetched fresh (AI.md PART 9 "HTTP Cache
		// Headers") — the versioned static assets they reference are what
		// gets the long-lived cache instead. The ETag still lets an
		// intermediary that ignores no-store revalidate against the build.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("ETag", `"`+assetStamp+`"`)
		// Version-change purge (AI.md PART 9 "Version-Change Purge
		// (Clear-Site-Data)"): evict a stale browser cache/service worker in
		// one shot when the client's build cookie disagrees with this build.
		applyVersionPurge(w, r, assetStamp)
		return t.ExecuteTemplate(w, "base", data)
	}
}

// NewTemplateExecutor returns a function that renders a named page template
// (layout+partials+page) into an arbitrary io.Writer, without touching HTTP
// headers or the status line. error.go's themed error-page path (AI.md PART
// 16 "Error Pages (MUST Match Theme)") uses this to render into a buffer
// first and only commit the write to the real http.ResponseWriter once the
// render succeeds — the "guaranteed response" pattern: a template failure
// must never corrupt a partially-written response, so the caller falls back
// to the minimal plain-text response untouched on error.
func NewTemplateExecutor(assetStamp string) func(w io.Writer, page string, data interface{}) error {
	base := buildBaseTemplate(assetStamp)
	return func(w io.Writer, page string, data interface{}) error {
		t, err := base.Clone()
		if err != nil {
			return err
		}
		t, err = t.ParseFS(templateFS, "template/page/"+page)
		if err != nil {
			return err
		}
		return t.ExecuteTemplate(w, "base", data)
	}
}

// StaticHandler serves embedded static files
func StaticHandler() http.Handler {
	// Strip the "static" prefix from the embedded FS
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(staticContent))
}
