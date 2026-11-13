package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
)

type atomFeed struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2005/Atom feed"`
	ID      string      `xml:"id"`
	Title   string      `xml:"title"`
	Updated string      `xml:"updated"`
	Self    atomLink    `xml:"link"`
	Entries []atomEntry `xml:"entry,omitempty"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

type atomEntry struct {
	ID      string `xml:"id"`
	Title   string `xml:"title"`
	Updated string `xml:"updated"`
}

type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Version string     `xml:"version,attr"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Title       string     `xml:"title"`
	Link        string     `xml:"link"`
	Description string     `xml:"description"`
	Items       []rssEntry `xml:"item,omitempty"`
}

type rssEntry struct {
	Title string `xml:"title"`
	Link  string `xml:"link"`
	GUID  string `xml:"guid"`
}

func (s *Server) feedHandler(atom bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := configFeed(s)
		if !cfg.Enabled {
			http.NotFound(w, r)
			return
		}
		title := strings.TrimSpace(cfg.Title)
		if title == "" {
			title = "IPGaze"
			if s.config != nil && strings.TrimSpace(s.config.Server.Branding.Title) != "" {
				title = strings.TrimSpace(s.config.Server.Branding.Title)
			}
		}
		now := s.feedLastModified()
		feedURL := netutil.BuildURL(r, s.getTrust(), map[bool]string{true: "/feed.xml", false: "/rss.xml"}[atom])
		var body []byte
		var err error
		contentType := "application/rss+xml; charset=utf-8"
		if atom {
			contentType = "application/atom+xml; charset=utf-8"
			body, err = xml.Marshal(atomFeed{ID: feedURL, Title: title, Updated: now.Format(time.RFC3339), Self: atomLink{Href: feedURL, Rel: "self"}})
		} else {
			body, err = xml.Marshal(rssFeed{Version: "2.0", Channel: rssChannel{Title: title, Link: feedURL, Description: title}})
		}
		if err != nil {
			http.Error(w, "feed generation failed", http.StatusInternalServerError)
			return
		}
		body = append([]byte(xml.Header), body...)
		body = append(body, '\n')
		digest := sha256.Sum256(body)
		etag := `"` + hex.EncodeToString(digest[:]) + `"`
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", now.UTC().Format(http.TimeFormat))
		if etagMatches(r.Header.Get("If-None-Match"), etag) || (r.Header.Get("If-None-Match") == "" && modifiedSince(r, now)) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
}

func configFeed(s *Server) config.FeedConfig {
	if s.config == nil {
		return config.DefaultSEOConfig().Feed
	}
	return s.config.Server.SEO.Feed
}

func (s *Server) feedLastModified() time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s.BuildDate); err == nil {
			return t.UTC().Truncate(time.Second)
		}
	}
	if !s.StartTime.IsZero() {
		return s.StartTime.UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}

func modifiedSince(r *http.Request, modified time.Time) bool {
	value := r.Header.Get("If-Modified-Since")
	if value == "" {
		return false
	}
	t, err := http.ParseTime(value)
	return err == nil && !modified.Truncate(time.Second).After(t)
}
