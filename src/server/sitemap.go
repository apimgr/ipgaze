package server

import (
	"encoding/xml"
	"net/http"
	"time"

	"github.com/apimgr/ipgaze/src/netutil"
)

// sitemapURL is one <url> entry of the sitemaps.org 0.9 schema.
type sitemapURL struct {
	Loc        string `xml:"loc"`
	LastMod    string `xml:"lastmod"`
	ChangeFreq string `xml:"changefreq"`
	Priority   string `xml:"priority"`
}

// sitemapURLSet is the document root of a sitemaps.org 0.9 sitemap.
type sitemapURLSet struct {
	XMLName xml.Name     `xml:"urlset"`
	Xmlns   string       `xml:"xmlns,attr"`
	URLs    []sitemapURL `xml:"url"`
}

// sitemapNamespace is the fixed schema URI required by the sitemap protocol.
const sitemapNamespace = "http://www.sitemaps.org/schemas/sitemap/0.9"

// sitemapEntry describes one crawlable path before it is resolved against the
// request's own scheme and host.
type sitemapEntry struct {
	path       string
	changeFreq string
	priority   string
}

// sitemapEntries lists every path that AI.md PART 24 "Sitemap Generation Rules"
// allows in the sitemap: the homepage at priority 1.0/daily, the public
// informational pages at 0.8/weekly, and the API documentation pages at
// 0.7/weekly. Nothing under /api/ and no authenticated server-management page
// is ever listed.
var sitemapEntries = []sitemapEntry{
	{path: "/", changeFreq: "daily", priority: "1.0"},
	{path: "/server/about", changeFreq: "weekly", priority: "0.8"},
	{path: "/server/help", changeFreq: "weekly", priority: "0.8"},
	{path: "/server/privacy", changeFreq: "weekly", priority: "0.8"},
	{path: "/server/terms", changeFreq: "weekly", priority: "0.8"},
	{path: "/server/contact", changeFreq: "weekly", priority: "0.8"},
	{path: "/server/docs/swagger", changeFreq: "weekly", priority: "0.7"},
	{path: "/server/docs/graphql", changeFreq: "weekly", priority: "0.7"},
}

// sitemapLastMod returns the W3C date used for every <lastmod>. The build
// timestamp is the moment the served content last changed; the process start
// time is the fallback for a binary built without the ldflag.
func (s *Server) sitemapLastMod() string {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s.BuildDate); err == nil {
			return t.UTC().Format("2006-01-02")
		}
	}
	if !s.StartTime.IsZero() {
		return s.StartTime.UTC().Format("2006-01-02")
	}
	return time.Now().UTC().Format("2006-01-02")
}

// sitemapHandler serves the dynamically generated /sitemap.xml required of
// every project by AI.md PART 24. It honours server.seo.sitemap.enabled and
// caps the document at server.seo.sitemap.max_urls.
func (s *Server) sitemapHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.config != nil && !s.config.Server.SEO.Sitemap.Enabled {
			http.NotFound(w, r)
			return
		}
		maxURLs := len(sitemapEntries)
		if s.config != nil && s.config.Server.SEO.Sitemap.MaxURLs > 0 &&
			s.config.Server.SEO.Sitemap.MaxURLs < maxURLs {
			maxURLs = s.config.Server.SEO.Sitemap.MaxURLs
		}
		lastMod := s.sitemapLastMod()
		set := sitemapURLSet{Xmlns: sitemapNamespace}
		for _, entry := range sitemapEntries[:maxURLs] {
			set.URLs = append(set.URLs, sitemapURL{
				Loc:        netutil.BuildURL(r, s.getTrust(), entry.path),
				LastMod:    lastMod,
				ChangeFreq: entry.changeFreq,
				Priority:   entry.priority,
			})
		}
		body, err := xml.MarshalIndent(set, "", "  ")
		if err != nil {
			http.Error(w, "sitemap unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		w.Write([]byte(xml.Header))
		w.Write(body)
		w.Write([]byte("\n"))
	}
}
