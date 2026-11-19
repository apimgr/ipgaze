package handler

import (
	"container/list"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/security"
)

const maxContactRequestBytes = 16 << 10

var errContactFormToken = errors.New("contact form token invalid")

var contactRateState = struct {
	sync.Mutex
	events map[string][]time.Time
}{events: make(map[string][]time.Time)}

var contactDuplicateState = struct {
	sync.Mutex
	items map[string]*list.Element
	lru   list.List
}{items: make(map[string]*list.Element)}

var contactStrikeState = struct {
	sync.Mutex
	events map[string][]time.Time
	bans   map[string]time.Time
}{events: make(map[string][]time.Time), bans: make(map[string]time.Time)}

type contactDuplicateEntry struct {
	key       string
	createdAt time.Time
}

var contactLinkPattern = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*://[^\s<>()]+|www\.[^\s<>()]+|\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?:/[^\s<>()]*)?)`)
var contactMarkupPattern = regexp.MustCompile(`(?i)<\s*/?\s*[a-z!]|</|<!|\[(?:url|img|b)(?:\s|=|\])|\[/`)

type contactRateLimitError struct {
	RetryAfter time.Duration
	Reason     string
}

func (e *contactRateLimitError) Error() string { return "contact rate limit exceeded" }

type contactRateReservation struct {
	keys      []string
	reserved  time.Time
	committed bool
}

func (r *contactRateReservation) commit() {
	if r != nil {
		r.committed = true
	}
}

func (r *contactRateReservation) rollback() {
	if r == nil || r.committed {
		return
	}
	contactRateState.Lock()
	defer contactRateState.Unlock()
	for _, key := range r.keys {
		times := contactRateState.events[key]
		for index := len(times) - 1; index >= 0; index-- {
			if times[index].Equal(r.reserved) {
				times = append(times[:index], times[index+1:]...)
				break
			}
		}
		if len(times) == 0 {
			delete(contactRateState.events, key)
		} else {
			contactRateState.events[key] = times
		}
	}
}

func (h *PagesHandler) newContactFormToken(now time.Time) string {
	if h.DB == nil {
		return ""
	}
	secret, err := security.GetOrCreateSecret(h.DB, security.SecretInstallationSecret)
	if err != nil {
		return ""
	}
	issuedAt := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("contact-form|" + issuedAt))
	return issuedAt + "." + hex.EncodeToString(mac.Sum(nil))
}

func (h *PagesHandler) verifyContactFormToken(token string, now time.Time) bool {
	if h.DB == nil {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(parts[1]) != sha256.Size*2 {
		return false
	}
	issuedAt, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	cfg := h.contactAntispamConfig()
	issued := time.Unix(issuedAt, 0)
	age := now.Sub(issued)
	if age < 0 || cfg.MinFillSeconds > 0 && age < time.Duration(cfg.MinFillSeconds)*time.Second || cfg.MaxAgeSeconds > 0 && age > time.Duration(cfg.MaxAgeSeconds)*time.Second {
		return false
	}
	provided, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	secret, err := security.GetOrCreateSecret(h.DB, security.SecretInstallationSecret)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("contact-form|" + parts[0]))
	return hmac.Equal(provided, mac.Sum(nil))
}

func (h *PagesHandler) contactAntispamConfig() config.ContactAntispamConfig {
	if h.Config == nil {
		return config.DefaultConfig().Pages.Contact.Antispam
	}
	return h.Config.Pages.Contact.Antispam
}

func contactContentBlockReason(req ContactRequest, cfg config.ContactAntispamConfig) string {
	name := strings.ToLower(req.Name)
	subject := strings.ToLower(req.Subject)
	message := strings.ToLower(req.Message)
	if cfg.RejectMarkup {
		for _, field := range []string{name, subject, message} {
			decoded := html.UnescapeString(field)
			if contactMarkupPattern.MatchString(field) || decoded != field && (strings.Contains(decoded, "<") || strings.Contains(decoded, ">")) {
				return "markup"
			}
		}
	}
	var hosts []string
	for index, field := range []string{name, subject, message} {
		links := contactLinkPattern.FindAllString(field, -1)
		if cfg.MaxLinks > 0 && index < 2 && len(links) > 0 {
			return "content"
		}
		if index == 2 && cfg.MaxLinks > 0 && len(links) > cfg.MaxLinks {
			return "content"
		}
		for _, link := range links {
			host := contactLinkHost(link)
			if host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	for _, word := range cfg.BlockedWords {
		word = strings.ToLower(strings.TrimSpace(word))
		if word != "" && (strings.Contains(name, word) || strings.Contains(subject, word) || strings.Contains(message, word)) {
			return "content"
		}
	}
	for _, host := range hosts {
		for _, blocked := range cfg.BlockedLinkDomains {
			blocked = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(blocked)), ".")
			if blocked != "" && (host == blocked || strings.HasSuffix(host, "."+blocked)) {
				return "content"
			}
		}
	}
	if at := strings.LastIndex(req.Email, "@"); at >= 0 {
		domain := strings.ToLower(strings.TrimSpace(req.Email[at+1:]))
		for _, blocked := range cfg.BlockedEmailDomains {
			if domain == strings.ToLower(strings.TrimSpace(blocked)) {
				return "content"
			}
		}
	}
	return ""
}

func contactContentBlocked(req ContactRequest, cfg config.ContactAntispamConfig) bool {
	return contactContentBlockReason(req, cfg) != ""
}

func contactLinkHost(link string) string {
	value := strings.TrimRight(link, ".,!?;:)")
	if strings.HasPrefix(strings.ToLower(value), "www.") {
		value = "https://" + value
	} else if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
}

func isOverlayContactRequest(h *PagesHandler, r *http.Request) bool {
	return r != nil && (netutil.IsTorRequest(r, h.Trust) || netutil.IsI2PRequest(r, h.Trust))
}

func (h *PagesHandler) contactBan(ip string, r *http.Request, now time.Time) time.Duration {
	if isOverlayContactRequest(h, r) {
		return 0
	}
	cfg := h.contactAntispamConfig()
	if cfg.Strikes <= 0 || cfg.BanHours <= 0 || ip == "" {
		return 0
	}
	window, err := time.ParseDuration(strings.TrimSpace(cfg.Window))
	if err != nil || window <= 0 {
		window = time.Hour
	}
	contactStrikeState.Lock()
	defer contactStrikeState.Unlock()
	for key, until := range contactStrikeState.bans {
		if !until.After(now) {
			delete(contactStrikeState.bans, key)
			delete(contactStrikeState.events, key)
		}
	}
	if until := contactStrikeState.bans[ip]; until.After(now) {
		return until.Sub(now)
	}
	cutoff := now.Add(-window)
	events := contactStrikeState.events[ip]
	kept := events[:0]
	for _, event := range events {
		if event.After(cutoff) {
			kept = append(kept, event)
		}
	}
	if len(kept) == 0 {
		delete(contactStrikeState.events, ip)
	} else {
		contactStrikeState.events[ip] = kept
	}
	return 0
}

func (h *PagesHandler) strikeContact(ip string, r *http.Request, reason string, now time.Time) time.Duration {
	if reason != "honeypot" && reason != "captcha" && reason != "content" && reason != "markup" && reason != "duplicate" || isOverlayContactRequest(h, r) {
		return 0
	}
	cfg := h.contactAntispamConfig()
	if cfg.Strikes <= 0 || cfg.BanHours <= 0 || ip == "" {
		return 0
	}
	window, err := time.ParseDuration(strings.TrimSpace(cfg.Window))
	if err != nil || window <= 0 {
		window = time.Hour
	}
	contactStrikeState.Lock()
	defer contactStrikeState.Unlock()
	cutoff := now.Add(-window)
	events := contactStrikeState.events[ip]
	kept := events[:0]
	for _, event := range events {
		if event.After(cutoff) {
			kept = append(kept, event)
		}
	}
	if _, tracked := contactStrikeState.events[ip]; !tracked && len(contactStrikeState.events) >= 65536 {
		var oldestIP string
		var oldest time.Time
		for candidate, candidateEvents := range contactStrikeState.events {
			if _, banned := contactStrikeState.bans[candidate]; banned || len(candidateEvents) == 0 {
				continue
			}
			if oldestIP == "" || candidateEvents[len(candidateEvents)-1].Before(oldest) {
				oldestIP = candidate
				oldest = candidateEvents[len(candidateEvents)-1]
			}
		}
		if oldestIP == "" {
			var earliestBan time.Time
			for candidate, until := range contactStrikeState.bans {
				if oldestIP == "" || until.Before(earliestBan) {
					oldestIP = candidate
					earliestBan = until
				}
			}
		}
		if oldestIP == "" {
			return 0
		}
		delete(contactStrikeState.events, oldestIP)
		delete(contactStrikeState.bans, oldestIP)
	}
	kept = append(kept, now)
	contactStrikeState.events[ip] = kept
	if len(kept) >= cfg.Strikes {
		until := now.Add(time.Duration(cfg.BanHours) * time.Hour)
		if len(contactStrikeState.bans) >= 65536 {
			earliestIP := ""
			earliestBan := time.Time{}
			for candidate, candidateUntil := range contactStrikeState.bans {
				if earliestIP == "" || candidateUntil.Before(earliestBan) {
					earliestIP = candidate
					earliestBan = candidateUntil
				}
			}
			delete(contactStrikeState.bans, earliestIP)
			delete(contactStrikeState.events, earliestIP)
		}
		contactStrikeState.bans[ip] = until
		return until.Sub(now)
	}
	return 0
}

func contactDuplicateKey(req ContactRequest) string {
	normalize := func(value string) string {
		return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
	}
	digest := sha256.Sum256([]byte(normalize(req.Email) + "\x00" + normalize(req.Subject) + "\x00" + normalize(req.Message)))
	return hex.EncodeToString(digest[:])
}

func duplicateContactSubmission(req ContactRequest, now time.Time, window time.Duration, remember bool) bool {
	if window <= 0 {
		return false
	}
	key := contactDuplicateKey(req)
	cutoff := now.Add(-window)
	contactDuplicateState.Lock()
	defer contactDuplicateState.Unlock()
	for element := contactDuplicateState.lru.Front(); element != nil; {
		next := element.Next()
		entry := element.Value.(contactDuplicateEntry)
		if !entry.createdAt.After(cutoff) {
			delete(contactDuplicateState.items, entry.key)
			contactDuplicateState.lru.Remove(element)
		}
		element = next
	}
	if element, exists := contactDuplicateState.items[key]; exists {
		contactDuplicateState.lru.MoveToFront(element)
		return true
	}
	if remember {
		element := contactDuplicateState.lru.PushFront(contactDuplicateEntry{key: key, createdAt: now})
		contactDuplicateState.items[key] = element
		if contactDuplicateState.lru.Len() > 10000 {
			oldest := contactDuplicateState.lru.Back()
			delete(contactDuplicateState.items, oldest.Value.(contactDuplicateEntry).key)
			contactDuplicateState.lru.Remove(oldest)
		}
	}
	return false
}

func validateContactReportShape(req ContactRequest) bool {
	fields := []string{
		req.Name, req.Handle, req.Email, req.SecurityID, req.ResearcherGPG,
		req.AffectedComponent, req.AffectedEndpoint, req.Severity, req.Summary,
		req.StepsToReproduce, req.Impact, req.SuggestedFix, req.CreditPreference,
	}
	if !validContactTextFields(fields, 0, 2) || strings.ContainsAny(req.Email, ",;<>\r\n") {
		return false
	}
	_, err := mail.ParseAddress(req.Email)
	return err == nil
}

func validateContactStandardShape(req ContactRequest) bool {
	fields := []string{req.Name, req.Email, req.Subject, req.Message}
	if !validContactTextFields(fields, 0, 1, 2) || strings.ContainsAny(req.Email, ",;<>\r\n") {
		return false
	}
	_, err := mail.ParseAddress(req.Email)
	return err == nil
}

func validContactTextFields(fields []string, rejectControls ...int) bool {
	noControl := make(map[int]struct{}, len(rejectControls))
	for _, index := range rejectControls {
		noControl[index] = struct{}{}
	}
	for index, field := range fields {
		if !utf8.ValidString(field) {
			return false
		}
		_, rejectAllControls := noControl[index]
		for _, r := range field {
			if unicode.IsControl(r) && (rejectAllControls || r != '\n' && r != '\r' && r != '\t') || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 || r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff {
				return false
			}
		}
	}
	return true
}

func (h *PagesHandler) allowContactRate(ip, email string, request *http.Request, now time.Time) *contactRateLimitError {
	reservation, limitErr := h.reserveContactRate(ip, email, request, now)
	if limitErr == nil {
		reservation.commit()
	}
	return limitErr
}

func (h *PagesHandler) reserveContactRate(ip, email string, request *http.Request, now time.Time) (*contactRateReservation, *contactRateLimitError) {
	cfg := h.contactAntispamConfig()
	window, err := time.ParseDuration(strings.TrimSpace(cfg.Window))
	if err != nil || window <= 0 {
		window = time.Hour
	}
	keys := make([]struct {
		key    string
		limit  int
		reason string
	}, 0, 3)
	isOverlay := request != nil && (netutil.IsTorRequest(request, h.Trust) || netutil.IsI2PRequest(request, h.Trust))
	if cfg.PerIP > 0 && !isOverlay {
		keys = append(keys, struct {
			key    string
			limit  int
			reason string
		}{"ip:" + ip, cfg.PerIP, "rate_ip"})
	}
	if cfg.PerEmail > 0 {
		keys = append(keys, struct {
			key    string
			limit  int
			reason string
		}{"email:" + strings.ToLower(strings.TrimSpace(email)), cfg.PerEmail, "rate_email"})
	}
	if cfg.Global > 0 {
		keys = append(keys, struct {
			key    string
			limit  int
			reason string
		}{"global", cfg.Global, "rate_global"})
	}
	if len(keys) == 0 {
		return &contactRateReservation{}, nil
	}
	cutoff := now.Add(-window)
	contactRateState.Lock()
	defer contactRateState.Unlock()
	for key, times := range contactRateState.events {
		kept := times[:0]
		for _, timestamp := range times {
			if timestamp.After(cutoff) {
				kept = append(kept, timestamp)
			}
		}
		if len(kept) == 0 {
			delete(contactRateState.events, key)
		} else {
			contactRateState.events[key] = kept
		}
	}
	for _, entry := range keys {
		times := contactRateState.events[entry.key]
		if len(times) >= entry.limit {
			return nil, &contactRateLimitError{RetryAfter: times[0].Add(window).Sub(now), Reason: entry.reason}
		}
	}
	if len(contactRateState.events) > 65536 {
		return nil, &contactRateLimitError{RetryAfter: time.Minute, Reason: "rate_global"}
	}
	for _, entry := range keys {
		contactRateState.events[entry.key] = append(contactRateState.events[entry.key], now)
	}
	reservedKeys := make([]string, 0, len(keys))
	for _, entry := range keys {
		reservedKeys = append(reservedKeys, entry.key)
	}
	return &contactRateReservation{keys: reservedKeys, reserved: now}, nil
}

func contactRetryAfter(err *contactRateLimitError) string {
	if err == nil {
		return ""
	}
	seconds := int(err.RetryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprint(seconds)
}
