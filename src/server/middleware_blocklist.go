package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/apimgr/ipgaze/src/blocklist"
	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	applog "github.com/apimgr/ipgaze/src/log"
)

var submittedEmailPattern = regexp.MustCompile("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([\\pL\\pN.-]+)")

const maxBlocklistInspectionBody = 10 << 20

var errBlocklistInspectionLimit = errors.New("blocklist request body exceeds inspection limit")

// writeForbidden emits a content-negotiated 403 through writeNegotiatedError,
// so a browser blocked by BlocklistMiddleware or GeoIPMiddleware gets the
// themed error page AI.md 24407/24413 require rather than the bare unstyled
// text/plain body http.Error produced for every client alike.
func writeForbidden(w http.ResponseWriter, r *http.Request, msg string) {
	writeNegotiatedError(w, r, http.StatusForbidden, "", msg)
}

// BlocklistMiddleware checks the client IP against downloaded blocklists.
// If the IP is found in any blocklist it returns 403 Forbidden.
// Allowlisted IPs (set by AllowlistMiddleware) bypass this check.
// Private/internal IPs (loopback, RFC 1918, link-local) are never blocked:
// public threat blocklists such as firehol_level1 intentionally include
// bogon ranges (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, ...) for perimeter
// filtering of spoofed WAN traffic, and applying that data to a server's own
// loopback/private-network traffic would lock out legitimate local/admin
// access. This mirrors GeoIPMiddleware's isPrivateIP exemption.
// If lookup is nil the middleware is a no-op passthrough.
// lm receives a security.log entry for every block so Fail2ban can escalate a
// repeat offender (AI.md PART 11); a nil manager silently skips the file write.
func BlocklistMiddleware(lookup *blocklist.Lookup, lm *applog.Manager, configuredBodyLimit ...int64) func(http.Handler) http.Handler {
	inspectionLimit := int64(maxBlocklistInspectionBody)
	if len(configuredBodyLimit) > 0 && configuredBodyLimit[0] > 0 {
		inspectionLimit = configuredBodyLimit[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allowlisted IPs bypass blocklist checks.
			if IsAllowlisted(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}
			if lookup != nil {
				ip := extractIP(r)
				blockedDomains, inspectErr := matchingRequestBlocklistDomains(lookup, r, inspectionLimit)
				if inspectErr != nil {
					if errors.Is(inspectErr, errBlocklistInspectionLimit) {
						writePayloadTooLarge(w, r)
					} else {
						writeNegotiatedError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Request body could not be inspected")
					}
					return
				}
				blockedIP := !IsTorRequestContext(r.Context()) && ip != nil && !isPrivateIP(ip) && lookup.Contains(ip)
				if len(blockedDomains) > 0 || blockedIP {
					clientIP := "unknown"
					if ip != nil {
						clientIP = ip.String()
					}
					log.Printf("blocklist: blocked request from %s %s", clientIP, sanitizeLogValue(r.URL.Path))
					if len(blockedDomains) > 0 {
						for _, target := range blockedDomains {
							log.Printf("blocklist: blocked domain %s from source %s", sanitizeLogValue(target.domain), sanitizeLogValue(target.source))
						}
						if lm != nil {
							lm.WriteSecurity("Blocked request from blocklisted domain", sanitizeLogValue(blockedDomains[0].domain))
						}
					} else if lm != nil {
						lm.WriteSecurity("Blocked request from blocklisted IP", sanitizeLogValue(ip.String()))
					}
					lang := i18n.DetectLocale(r)
					writeForbidden(w, r, i18n.T(i18n.WithLang(r.Context(), lang), "errors.blocked_by_blocklist"))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

type blockedDomainTarget struct {
	domain string
	source string
}

func matchingRequestBlocklistDomains(lookup *blocklist.Lookup, r *http.Request, inspectionLimit int64) ([]blockedDomainTarget, error) {
	if lookup == nil || r == nil {
		return nil, nil
	}
	var matches []blockedDomainTarget
	seen := make(map[string]struct{})
	targets, err := requestBlocklistDomainTargets(r, inspectionLimit)
	if err != nil {
		return nil, err
	}
	for _, value := range targets {
		domain, ok := blocklist.NormalizeDomain(value)
		if !ok {
			continue
		}
		for _, source := range lookup.MatchingDomainSources(domain) {
			key := source + "\x00" + domain
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, blockedDomainTarget{domain: domain, source: source})
		}
	}
	return matches, nil
}

func requestBlocklistDomainTargets(r *http.Request, inspectionLimit int64) ([]string, error) {
	var targets []string
	referrer := r.Header.Get("Origin")
	if referrer == "" {
		referrer = r.Header.Get("Referer")
	}
	if referrer != "" {
		if parsed, err := url.Parse(referrer); err == nil {
			targets = append(targets, parsed.Hostname())
		}
	}
	for key, values := range r.URL.Query() {
		if isEmailField(key) {
			for _, value := range values {
				targets = append(targets, submittedEmailDomains(value)...)
			}
		}
		if isURLField(key) {
			targets = append(targets, values...)
		}
	}
	rawContentType := r.Header.Get("Content-Type")
	contentType := strings.ToLower(rawContentType)
	body, err := readAndRestoreBlocklistBody(r, inspectionLimit)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return targets, nil
	}
	switch {
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		if values, err := url.ParseQuery(string(body)); err == nil {
			for key, entries := range values {
				for _, value := range entries {
					if isEmailField(key) {
						targets = append(targets, submittedEmailDomains(value)...)
					}
					if isURLField(key) {
						targets = append(targets, value)
					}
				}
			}
		}
	case strings.Contains(contentType, "application/json") || strings.Contains(contentType, "+json"):
		var payload any
		if json.Unmarshal(body, &payload) == nil {
			targets = appendJSONBlocklistTargets(targets, payload)
		}
	case strings.HasPrefix(contentType, "text/plain") || strings.HasPrefix(contentType, "text/uri-list"):
		if target := submittedURLTarget(strings.TrimSpace(string(body))); target != "" {
			targets = append(targets, target)
		}
	case strings.Contains(contentType, "multipart/form-data"):
		if mediaType, params, err := mime.ParseMediaType(rawContentType); err == nil && mediaType == "multipart/form-data" {
			reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
			for {
				part, err := reader.NextPart()
				if err != nil {
					break
				}
				data, _ := io.ReadAll(io.LimitReader(part, maxBlocklistInspectionBody))
				name := part.FormName()
				value := string(data)
				if isEmailField(name) {
					targets = append(targets, submittedEmailDomains(value)...)
				}
				if isURLField(name) {
					targets = append(targets, value)
				}
				_ = part.Close()
			}
		}
	}
	return targets, nil
}

func readAndRestoreBlocklistBody(r *http.Request, inspectionLimit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	if inspectionLimit <= 0 {
		inspectionLimit = maxBlocklistInspectionBody
	}
	if r.ContentLength > inspectionLimit {
		return nil, errBlocklistInspectionLimit
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, inspectionLimit+1))
	if err != nil {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, errBlocklistInspectionLimit
		}
		return nil, err
	}
	if int64(len(body)) > inspectionLimit {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		return nil, errBlocklistInspectionLimit
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func appendJSONBlocklistTargets(targets []string, value any) []string {
	switch item := value.(type) {
	case map[string]any:
		for key, nested := range item {
			if isEmailField(key) {
				targets = appendEmailFieldValues(targets, nested)
			} else if isURLField(key) {
				targets = appendURLFieldValues(targets, nested)
			} else {
				targets = appendJSONBlocklistTargets(targets, nested)
			}
		}
	case []any:
		for _, nested := range item {
			targets = appendJSONBlocklistTargets(targets, nested)
		}
	}
	return targets
}

func appendEmailFieldValues(targets []string, value any) []string {
	switch item := value.(type) {
	case string:
		return append(targets, submittedEmailDomains(item)...)
	case []any:
		for _, nested := range item {
			targets = appendEmailFieldValues(targets, nested)
		}
	}
	return targets
}

func appendURLFieldValues(targets []string, value any) []string {
	switch item := value.(type) {
	case string:
		return append(targets, item)
	case []any:
		for _, nested := range item {
			targets = appendURLFieldValues(targets, nested)
		}
	}
	return targets
}

func submittedEmailDomains(value string) []string {
	matches := submittedEmailPattern.FindAllStringSubmatch(value, -1)
	domains := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			domains = append(domains, match[1])
		}
	}
	return domains
}

func submittedURLTarget(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	return value
}

func isEmailField(key string) bool {
	key = strings.ToLower(key)
	return key == "email" || key == "emails" || strings.HasSuffix(key, "_email") || strings.HasSuffix(key, "_emails")
}

func isURLField(key string) bool {
	key = strings.ToLower(key)
	return key == "url" || key == "urls" || key == "uri" || key == "uris" || key == "link" || key == "links" ||
		strings.HasSuffix(key, "_url") || strings.HasSuffix(key, "_urls") || strings.HasSuffix(key, "_uri") || strings.HasSuffix(key, "_uris") ||
		strings.HasSuffix(key, "_link") || strings.HasSuffix(key, "_links")
}
