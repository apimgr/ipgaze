package server

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// faviconSourcePNG is the embedded 32x32 PNG wrapped into the ICO container
// served at /favicon.ico (AI.md PART 24 "Static Files": embedded default,
// customizable).
const faviconSourcePNG = "static/icons/favicon-32.png"

// faviconICO caches the ICO container built from faviconSourcePNG. The wrapper
// is deterministic, so it is built once on first request rather than on every
// browser probe.
var (
	faviconOnce  sync.Once
	faviconBytes []byte
)

// buildFaviconICO wraps a PNG in a single-image ICO container. Windows Vista
// and every current browser accept a PNG payload inside ICO, so the same
// 32x32 asset backs both the <link rel="icon"> tags and /favicon.ico without
// shipping a second copy of the image.
func buildFaviconICO(png []byte) []byte {
	var buf bytes.Buffer
	// ICONDIR: reserved, type 1 (icon), one image.
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))
	// ICONDIRENTRY: 32x32, no palette, 1 plane, 32bpp.
	buf.WriteByte(32)
	buf.WriteByte(32)
	buf.WriteByte(0)
	buf.WriteByte(0)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(32))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(png)))
	// The image data begins immediately after the 6-byte ICONDIR and the
	// single 16-byte ICONDIRENTRY.
	_ = binary.Write(&buf, binary.LittleEndian, uint32(22))
	buf.Write(png)
	return buf.Bytes()
}

// defaultFaviconICO returns the embedded default favicon, or nil when the
// source PNG is missing from the embedded filesystem.
func defaultFaviconICO() []byte {
	faviconOnce.Do(func() {
		png, err := staticFS.ReadFile(faviconSourcePNG)
		if err != nil {
			return
		}
		faviconBytes = buildFaviconICO(png)
	})
	return faviconBytes
}

// faviconHandler serves /favicon.ico (AI.md PART 24 "Static Files"). A
// configured branding.favicon_url takes precedence and is redirected to, so
// operators can point at their own asset without rebuilding the binary;
// otherwise the embedded default is served.
func (s *Server) faviconHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.config != nil {
			if custom := strings.TrimSpace(s.config.Server.Branding.FaviconURL); custom != "" {
				http.Redirect(w, r, custom, http.StatusFound)
				return
			}
		}
		ico := defaultFaviconICO()
		if len(ico) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		// The favicon changes only with the build, so it is safe to cache for
		// a day while still letting a redeploy replace it within a day.
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Length", strconv.Itoa(len(ico)))
		// net/http discards the body for HEAD, so the same write path serves
		// both methods.
		if _, err := w.Write(ico); err != nil {
			return
		}
	}
}
