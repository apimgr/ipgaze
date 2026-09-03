package email

import (
	"bytes"
	"crypto/tls"
	"embed"
	"fmt"
	"html"
	"io/fs"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/apimgr/ipgaze/src/common/i18n"
)

// defaultTemplateFS holds the embedded default email templates.
//
//go:embed templates/*.txt
var defaultTemplateFS embed.FS

// SMTPConfig holds SMTP configuration per AI.md PART 17.
type SMTPConfig struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// FromName is the optional display name for the From header
	// (maps to notifications.email.from.name / SMTP_FROM_NAME, AI.md PART 17).
	FromName string
	// TLS mode: auto | starttls | tls | none. Default: auto.
	TLS string
}

// EmailManager handles email sending per AI.md PART 17.
type EmailManager struct {
	config    SMTPConfig
	queue     chan *Message
	mu        sync.RWMutex
	started   bool
	stopCh    chan struct{}
	configDir string
}

// Message represents an email message.
type Message struct {
	To      []string
	Subject string
	Body    string
	HTML    bool
}

// Template represents a named email template per AI.md PART 17.
// Templates use simple {variable} syntax. First line is "Subject: ...",
// then "---" separator, then the plain-text body.
type Template struct {
	Name    string
	Subject string
	Body    string
}

// NewEmailManager creates a new email manager.
// configDir is the application config directory for template overrides.
func NewEmailManager(cfg SMTPConfig, configDir string) *EmailManager {
	return &EmailManager{
		config:    cfg,
		queue:     make(chan *Message, 100),
		configDir: configDir,
	}
}

// IsEnabled returns true if SMTP is configured and email is active.
func (m *EmailManager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.Enabled && m.config.Host != ""
}

// Send queues an email for delivery. Returns an error if SMTP is not configured.
func (m *EmailManager) Send(msg *Message) error {
	if !m.IsEnabled() {
		return fmt.Errorf("email not configured")
	}

	select {
	case m.queue <- msg:
		return nil
	default:
		return fmt.Errorf("email queue full")
	}
}

// SendDirect sends an email immediately as a multipart MIME message (HTML + plain text).
// TLS handling follows the four modes defined in AI.md PART 17 (smtp.tls / SMTP_TLS):
//   - "none": plaintext, no TLS at all
//   - "starttls": connect plaintext, then explicit STARTTLS upgrade (fails if unsupported)
//   - "tls": implicit TLS from the start of the connection (typically port 465)
//   - "auto" (default): implicit TLS when port is 465, otherwise STARTTLS if the
//     server advertises it, else falls back to plaintext
func (m *EmailManager) SendDirect(msg *Message) error {
	if !m.IsEnabled() {
		return fmt.Errorf("email not configured")
	}

	// The envelope sender (client.Mail) uses the bare address; the From
	// header may carry a display name when configured (AI.md PART 17).
	headerFrom := m.config.From
	if m.config.FromName != "" {
		headerFrom = fmt.Sprintf("%s <%s>", m.config.FromName, m.config.From)
	}
	body, err := buildMultipartBody(msg.Subject, msg.Body, headerFrom, msg.To)
	if err != nil {
		return fmt.Errorf("email: failed to build message body: %w", err)
	}

	return sendWithTLSMode(m.config, msg.To, body)
}

// sendWithTLSMode connects to the configured SMTP server and sends msg,
// branching on cfg.TLS per AI.md PART 17.
func sendWithTLSMode(cfg SMTPConfig, to []string, body []byte) error {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))

	tlsMode := strings.ToLower(strings.TrimSpace(cfg.TLS))
	if tlsMode == "" {
		tlsMode = "auto"
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second}

	var conn net.Conn
	var err error
	// "tls" (or "auto" on the implicit-TLS port 465) dials straight into TLS.
	if tlsMode == "tls" || (tlsMode == "auto" && cfg.Port == 465) {
		tlsConfig := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("email: dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("email: new client: %w", err)
	}
	defer client.Close()

	// "starttls" (or "auto" on a non-implicit-TLS port) upgrades in place.
	if tlsMode == "starttls" || (tlsMode == "auto" && cfg.Port != 465) {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("email: starttls: %w", err)
			}
		} else if tlsMode == "starttls" {
			return fmt.Errorf("email: server does not support STARTTLS")
		} else if cfg.Username != "" && cfg.Password != "" {
			// auto mode: refuse to send credentials/body in cleartext when the
			// server does not advertise STARTTLS. Use TLS mode "none" to opt in.
			return fmt.Errorf("email: server does not support STARTTLS; refusing cleartext with credentials (set tls: none to override)")
		}
		// tlsMode == "auto" with no STARTTLS and no credentials: plaintext.
	}
	// tlsMode == "none": always plaintext, even if STARTTLS is advertised.

	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email: auth: %w", err)
		}
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("email: mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("email: rcpt to %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email: data: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("email: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: close data: %w", err)
	}

	return client.Quit()
}

// buildMultipartBody constructs a multipart/alternative MIME message with plain text and HTML parts.
func buildMultipartBody(subject, plainText, from string, to []string) ([]byte, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	boundary := writer.Boundary()

	// Write headers
	buf.Reset()
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&buf, "Subject: %s\r\n", subject)
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n", boundary)
	fmt.Fprintf(&buf, "\r\n")

	// Plain text part
	textHeader := make(textproto.MIMEHeader)
	textHeader.Set("Content-Type", "text/plain; charset=UTF-8")
	textHeader.Set("Content-Transfer-Encoding", "quoted-printable")
	textPart, err := writer.CreatePart(textHeader)
	if err != nil {
		return nil, err
	}
	qpWriter := quotedprintable.NewWriter(textPart)
	if _, err = qpWriter.Write([]byte(plainText)); err != nil {
		return nil, err
	}
	if err = qpWriter.Close(); err != nil {
		return nil, err
	}

	// HTML part
	htmlHeader := make(textproto.MIMEHeader)
	htmlHeader.Set("Content-Type", "text/html; charset=UTF-8")
	htmlHeader.Set("Content-Transfer-Encoding", "quoted-printable")
	htmlPart, err := writer.CreatePart(htmlHeader)
	if err != nil {
		return nil, err
	}
	qpWriter = quotedprintable.NewWriter(htmlPart)
	htmlBody := plainToHTML(plainText)
	if _, err = qpWriter.Write([]byte(htmlBody)); err != nil {
		return nil, err
	}
	if err = qpWriter.Close(); err != nil {
		return nil, err
	}

	if err = writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// plainToHTML converts a plain text email body to a simple styled HTML version.
func plainToHTML(plain string) string {
	escaped := html.EscapeString(plain)
	lines := strings.Split(escaped, "\n")
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><meta charset=\"UTF-8\">")
	sb.WriteString("<style>body{font-family:sans-serif;max-width:600px;margin:0 auto;padding:20px;color:#222;}")
	sb.WriteString("pre{white-space:pre-wrap;}</style></head><body><pre>")
	for _, line := range lines {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	sb.WriteString("</pre></body></html>")
	return sb.String()
}

// Start begins processing the email queue.
func (m *EmailManager) Start() {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	stopCh := make(chan struct{})
	m.stopCh = stopCh
	m.mu.Unlock()

	go m.processQueue(stopCh)
}

// Stop halts the email queue processor. Closing stopCh immediately unblocks
// processQueue's select even while it is waiting on an empty m.queue, so a
// worker goroutine started by Start() never outlives Stop() and a
// subsequent Start() never ends up with two goroutines racing to consume
// the same queue.
func (m *EmailManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return
	}
	m.started = false
	close(m.stopCh)
}

// processQueue drains the queue and sends each message until stopCh is
// closed by Stop().
func (m *EmailManager) processQueue(stopCh chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case msg := <-m.queue:
			if err := m.SendDirect(msg); err != nil {
				fmt.Printf("email: failed to send: %v\n", err)
			}
		}
	}
}

// LoadTemplate loads a named template. Checks {config_dir}/template/email/ first,
// then falls back to the embedded default templates.
func (m *EmailManager) LoadTemplate(name string) (*Template, error) {
	filename := name + ".txt"

	// Try config directory override first
	if m.configDir != "" {
		diskPath := filepath.Join(m.configDir, "template", "email", filename)
		if data, err := os.ReadFile(diskPath); err == nil {
			return parseTemplate(name, data)
		}
	}

	// Fall back to embedded templates
	data, err := defaultTemplateFS.ReadFile(filepath.Join("templates", filename))
	if err != nil {
		return nil, fmt.Errorf("template %q not found: %w", name, err)
	}
	return parseTemplate(name, data)
}

// parseTemplate parses a template file with "Subject: ..." + "---" + body format.
func parseTemplate(name string, data []byte) (*Template, error) {
	content := string(data)
	lines := strings.SplitN(content, "\n", -1)

	if len(lines) < 3 {
		return nil, fmt.Errorf("template %q: too short", name)
	}

	// First line: "Subject: ..."
	subjectLine := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(subjectLine, "Subject: ") {
		return nil, fmt.Errorf("template %q: missing Subject line", name)
	}
	subject := strings.TrimPrefix(subjectLine, "Subject: ")

	// Find separator "---"
	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			bodyStart = i + 1
			break
		}
	}
	if bodyStart < 0 {
		return nil, fmt.Errorf("template %q: missing --- separator", name)
	}

	body := strings.TrimSpace(strings.Join(lines[bodyStart:], "\n"))

	return &Template{
		Name:    name,
		Subject: subject,
		Body:    body,
	}, nil
}

// Render substitutes {variable} placeholders in the template subject and body.
func (t *Template) Render(vars map[string]string) (subject, body string) {
	subject = t.Subject
	body = t.Body
	for k, v := range vars {
		placeholder := "{" + k + "}"
		subject = strings.ReplaceAll(subject, placeholder, v)
		body = strings.ReplaceAll(body, placeholder, v)
	}
	return subject, body
}

// SendTemplate loads a template, renders it with vars, and sends it.
func (m *EmailManager) SendTemplate(templateName string, to []string, vars map[string]string) error {
	tmpl, err := m.LoadTemplate(templateName)
	if err != nil {
		return fmt.Errorf("email: %w", err)
	}

	subject, body := tmpl.Render(vars)
	return m.SendDirect(&Message{
		To:      to,
		Subject: subject,
		Body:    body,
	})
}

// localizedVarKeys are the template variables every email template draws
// from the locale files rather than from caller-supplied data.
var localizedVarKeys = []string{
	"subject", "heading", "from_line", "intro", "action",
	"label_time", "label_filename", "label_size", "label_error",
	"label_task", "label_event", "label_ip", "label_domain",
	"label_expires", "label_days_remaining", "label_new_expiry",
	"label_days_until_expiry", "label_next_retry", "label_channel",
	"label_current_version", "label_new_version", "label_previous_version",
}

// SendLocalizedTemplate renders templateName in lang, resolving every
// localized variable from the email.* locale namespace before falling
// through to the caller's data vars.
func (m *EmailManager) SendLocalizedTemplate(templateName, lang string, to []string, vars map[string]string) error {
	merged := make(map[string]string, len(vars)+len(localizedVarKeys))
	for _, k := range localizedVarKeys {
		key := "email." + templateName + "." + k
		if v := i18n.Translate(lang, key); v != "" && v != key {
			merged[k] = v
		}
	}
	for k, v := range vars {
		merged[k] = v
	}
	return m.SendTemplate(templateName, to, merged)
}

// DefaultTemplateNames returns the names of all embedded templates.
func DefaultTemplateNames() ([]string, error) {
	entries, err := fs.ReadDir(defaultTemplateFS, "templates")
	if err != nil {
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
			names = append(names, strings.TrimSuffix(e.Name(), ".txt"))
		}
	}
	return names, nil
}
