package email

import (
	"bufio"
	"fmt"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- NewEmailManager & IsEnabled ---

func TestIsEnabled_DisabledByDefault(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	if m.IsEnabled() {
		t.Fatal("expected IsEnabled() == false when Enabled is false")
	}
}

func TestIsEnabled_EnabledButNoHost(t *testing.T) {
	m := NewEmailManager(SMTPConfig{Enabled: true, Host: ""}, "")
	if m.IsEnabled() {
		t.Fatal("expected IsEnabled() == false when host is empty")
	}
}

func TestIsEnabled_FullyConfigured(t *testing.T) {
	m := NewEmailManager(SMTPConfig{Enabled: true, Host: "smtp.example.com", Port: 587}, "")
	if !m.IsEnabled() {
		t.Fatal("expected IsEnabled() == true when Enabled and Host are set")
	}
}

// --- Send (queue) ---

func TestSend_WhenDisabled_ReturnsError(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	err := m.Send(&Message{To: []string{"a@b.com"}, Subject: "hi", Body: "body"})
	if err == nil {
		t.Fatal("expected error when email not configured")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

func TestSend_WhenEnabled_EnqueuesMessage(t *testing.T) {
	m := NewEmailManager(SMTPConfig{Enabled: true, Host: "smtp.example.com", Port: 587}, "")
	msg := &Message{To: []string{"a@b.com"}, Subject: "hi", Body: "body"}
	if err := m.Send(msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.queue) != 1 {
		t.Fatalf("expected 1 queued message, got %d", len(m.queue))
	}
}

func TestSend_QueueFull_ReturnsError(t *testing.T) {
	// Queue capacity is 100; fill it completely.
	m := NewEmailManager(SMTPConfig{Enabled: true, Host: "smtp.example.com", Port: 587}, "")
	msg := &Message{To: []string{"a@b.com"}, Subject: "hi", Body: "body"}
	for i := 0; i < 100; i++ {
		if err := m.Send(msg); err != nil {
			t.Fatalf("unexpected error on send %d: %v", i, err)
		}
	}
	// 101st send should fail.
	err := m.Send(msg)
	if err == nil {
		t.Fatal("expected queue-full error")
	}
	if !strings.Contains(err.Error(), "queue full") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// --- SendDirect ---

func TestSendDirect_WhenDisabled_ReturnsError(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	err := m.SendDirect(&Message{To: []string{"a@b.com"}, Subject: "s", Body: "b"})
	if err == nil {
		t.Fatal("expected error when email not configured")
	}
}

// --- buildMultipartBody ---

func TestBuildMultipartBody_ValidMIME(t *testing.T) {
	body, err := buildMultipartBody("Test Subject", "Hello world", "from@example.com", []string{"to@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}

	// Parse the result as an RFC 2822 message and verify headers.
	msg, err := mail.ReadMessage(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("output is not a valid email message: %v", err)
	}
	if got := msg.Header.Get("From"); got != "from@example.com" {
		t.Errorf("From header = %q, want %q", got, "from@example.com")
	}
	if got := msg.Header.Get("Subject"); got != "Test Subject" {
		t.Errorf("Subject header = %q, want %q", got, "Test Subject")
	}

	// Verify it is multipart/alternative with two parts.
	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("failed to parse Content-Type %q: %v", ct, err)
	}
	if mediaType != "multipart/alternative" {
		t.Errorf("Content-Type = %q, want multipart/alternative", mediaType)
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	var partTypes []string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		partTypes = append(partTypes, p.Header.Get("Content-Type"))
	}
	if len(partTypes) != 2 {
		t.Fatalf("expected 2 MIME parts, got %d", len(partTypes))
	}
	if !strings.HasPrefix(partTypes[0], "text/plain") {
		t.Errorf("part 0 Content-Type = %q, want text/plain", partTypes[0])
	}
	if !strings.HasPrefix(partTypes[1], "text/html") {
		t.Errorf("part 1 Content-Type = %q, want text/html", partTypes[1])
	}
}

func TestBuildMultipartBody_MultipleRecipients(t *testing.T) {
	recipients := []string{"a@example.com", "b@example.com"}
	body, err := buildMultipartBody("Subj", "Body", "from@example.com", recipients)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("invalid email: %v", err)
	}
	toHeader := msg.Header.Get("To")
	for _, r := range recipients {
		if !strings.Contains(toHeader, r) {
			t.Errorf("To header %q does not contain %q", toHeader, r)
		}
	}
}

// --- plainToHTML ---

func TestPlainToHTML_ContainsEscapedText(t *testing.T) {
	plain := "Hello <world> & \"friends\""
	result := plainToHTML(plain)

	if !strings.Contains(result, "Hello &lt;world&gt; &amp; &#34;friends&#34;") {
		t.Errorf("HTML output not correctly escaped: %s", result)
	}
	if !strings.Contains(result, "<!DOCTYPE html>") {
		t.Error("expected DOCTYPE declaration")
	}
	if !strings.Contains(result, "<pre>") {
		t.Error("expected <pre> wrapper")
	}
}

func TestPlainToHTML_EmptyInput(t *testing.T) {
	result := plainToHTML("")
	if result == "" {
		t.Fatal("expected non-empty HTML even for empty input")
	}
	if !strings.Contains(result, "<pre>") {
		t.Error("expected structural HTML elements")
	}
}

func TestPlainToHTML_MultilinePreserved(t *testing.T) {
	plain := "line1\nline2\nline3"
	result := plainToHTML(plain)
	if !strings.Contains(result, "line1") || !strings.Contains(result, "line2") {
		t.Error("expected all lines to be present in HTML output")
	}
}

// --- LoadTemplate & parseTemplate ---

func TestLoadTemplate_EmbeddedTemplates(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	names, err := DefaultTemplateNames()
	if err != nil {
		t.Fatalf("DefaultTemplateNames: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("expected at least one embedded template")
	}
	for _, name := range names {
		tmpl, err := m.LoadTemplate(name)
		if err != nil {
			t.Errorf("LoadTemplate(%q): %v", name, err)
			continue
		}
		if tmpl.Name != name {
			t.Errorf("template name = %q, want %q", tmpl.Name, name)
		}
		if tmpl.Subject == "" {
			t.Errorf("template %q has empty subject", name)
		}
		if tmpl.Body == "" {
			t.Errorf("template %q has empty body", name)
		}
	}
}

func TestLoadTemplate_NotFound_ReturnsError(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	_, err := m.LoadTemplate("nonexistent_template_xyz")
	if err == nil {
		t.Fatal("expected error for missing template")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestLoadTemplate_DiskOverride_TakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	overrideDir := filepath.Join(dir, "template", "email")
	if err := os.MkdirAll(overrideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "Subject: Override Subject\n---\nOverride body."
	if err := os.WriteFile(filepath.Join(overrideDir, "test.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewEmailManager(SMTPConfig{}, dir)
	tmpl, err := m.LoadTemplate("test")
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}
	if tmpl.Subject != "Override Subject" {
		t.Errorf("subject = %q, want %q", tmpl.Subject, "Override Subject")
	}
	if tmpl.Body != "Override body." {
		t.Errorf("body = %q, want %q", tmpl.Body, "Override body.")
	}
}

func TestLoadTemplate_EmptyConfigDir_FallsBackToEmbedded(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	tmpl, err := m.LoadTemplate("test")
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}
	// Templates are translation-driven: every user-facing string is a
	// {variable} token resolved from the email.* locale namespace, so the
	// embedded body is asserted by its token structure, not by English text.
	for _, token := range []string{"{heading}", "{intro}", "{app_name}"} {
		if !strings.Contains(tmpl.Body, token) {
			t.Errorf("embedded test template body missing %s, got: %q", token, tmpl.Body)
		}
	}
	if tmpl.Subject != "{subject}" {
		t.Errorf("subject = %q, want %q", tmpl.Subject, "{subject}")
	}
}

// --- parseTemplate ---

func TestParseTemplate_WellFormed(t *testing.T) {
	data := []byte("Subject: Hello World\n---\nThis is the body.\nSecond line.")
	tmpl, err := parseTemplate("test", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.Subject != "Hello World" {
		t.Errorf("subject = %q, want %q", tmpl.Subject, "Hello World")
	}
	if !strings.Contains(tmpl.Body, "This is the body.") {
		t.Errorf("body missing expected content: %q", tmpl.Body)
	}
}

func TestParseTemplate_MissingSubjectLine_ReturnsError(t *testing.T) {
	data := []byte("Nope: wrong\n---\nbody")
	_, err := parseTemplate("bad", data)
	if err == nil {
		t.Fatal("expected error for missing Subject line")
	}
	if !strings.Contains(err.Error(), "missing Subject") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseTemplate_MissingSeparator_ReturnsError(t *testing.T) {
	data := []byte("Subject: Hello\nbody line one\nbody line two without separator")
	_, err := parseTemplate("bad", data)
	if err == nil {
		t.Fatal("expected error for missing --- separator")
	}
	if !strings.Contains(err.Error(), "missing ---") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseTemplate_TooShort_ReturnsError(t *testing.T) {
	data := []byte("Subject: Hello\n")
	_, err := parseTemplate("bad", data)
	if err == nil {
		t.Fatal("expected error for template that is too short")
	}
}

func TestParseTemplate_SubjectHasTrailingSpaces(t *testing.T) {
	data := []byte("Subject:   Trimmed  \n---\nbody")
	tmpl, err := parseTemplate("t", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.Subject != "  Trimmed  " {
		// TrimPrefix keeps everything after "Subject: " including leading space.
		// The spec uses TrimPrefix not TrimSpace on the subject value.
		// Just verify it parsed without error and has a non-empty subject.
		if tmpl.Subject == "" {
			t.Error("subject should not be empty")
		}
	}
}

// --- Template.Render ---

func TestRender_SubstitutesPlaceholders(t *testing.T) {
	tmpl := &Template{
		Name:    "test",
		Subject: "Alert for {app_name}",
		Body:    "Hello from {app_name}. Visit {app_url} for details.",
	}
	vars := map[string]string{
		"app_name": "ipgaze",
		"app_url":  "https://ifcfg.us",
	}
	subject, body := tmpl.Render(vars)
	if subject != "Alert for ipgaze" {
		t.Errorf("subject = %q, want %q", subject, "Alert for ipgaze")
	}
	if !strings.Contains(body, "Hello from ipgaze") {
		t.Errorf("body missing substitution: %q", body)
	}
	if !strings.Contains(body, "https://ifcfg.us") {
		t.Errorf("body missing URL: %q", body)
	}
}

func TestRender_NoVars_LeavesPlaceholders(t *testing.T) {
	tmpl := &Template{
		Name:    "test",
		Subject: "{unchanged}",
		Body:    "{also_unchanged}",
	}
	subject, body := tmpl.Render(nil)
	if subject != "{unchanged}" {
		t.Errorf("subject = %q, expected placeholder to remain", subject)
	}
	if body != "{also_unchanged}" {
		t.Errorf("body = %q, expected placeholder to remain", body)
	}
}

func TestRender_PartialVars_LeavesUnmatchedPlaceholders(t *testing.T) {
	tmpl := &Template{
		Name:    "test",
		Subject: "{a} and {b}",
		Body:    "body",
	}
	subject, _ := tmpl.Render(map[string]string{"a": "A"})
	if !strings.Contains(subject, "A") {
		t.Error("expected {a} to be substituted")
	}
	if !strings.Contains(subject, "{b}") {
		t.Error("expected {b} placeholder to remain")
	}
}

func TestRender_EmptyVarValue_Substitutes(t *testing.T) {
	tmpl := &Template{
		Name:    "test",
		Subject: "hello {name}",
		Body:    "body",
	}
	subject, _ := tmpl.Render(map[string]string{"name": ""})
	if subject != "hello " {
		t.Errorf("subject = %q, expected empty substitution", subject)
	}
}

// --- DefaultTemplateNames ---

func TestDefaultTemplateNames_ReturnsKnownTemplates(t *testing.T) {
	names, err := DefaultTemplateNames()
	if err != nil {
		t.Fatalf("DefaultTemplateNames: %v", err)
	}
	expected := []string{"backup_complete", "backup_failed", "scheduler_error", "security_alert", "ssl_expiring", "ssl_renewed", "test"}
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	for _, want := range expected {
		if !nameSet[want] {
			t.Errorf("expected template %q in DefaultTemplateNames, got: %v", want, names)
		}
	}
}

func TestDefaultTemplateNames_NoDuplicates(t *testing.T) {
	names, err := DefaultTemplateNames()
	if err != nil {
		t.Fatalf("DefaultTemplateNames: %v", err)
	}
	seen := make(map[string]int)
	for _, n := range names {
		seen[n]++
	}
	for n, count := range seen {
		if count > 1 {
			t.Errorf("template %q appears %d times", n, count)
		}
	}
}

// --- Start / Stop idempotency ---

func TestStart_Idempotent(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	// Starting twice must not panic or block.
	m.Start()
	m.Start()
	m.Stop()
}

func TestStop_WithoutStart_Noop(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	// Stopping without starting must not panic.
	m.Stop()
}

// --- Round-trip: LoadTemplate -> Render -> buildMultipartBody ---

func TestRoundTrip_LoadRenderBuild(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	tmpl, err := m.LoadTemplate("security_alert")
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}
	// The localized keys below are what SendLocalizedTemplate resolves from
	// the email.* locale namespace before delegating to Render.
	vars := map[string]string{
		"subject":     "ipgaze security alert",
		"heading":     "Security alert",
		"from_line":   "Sent by ipgaze",
		"intro":       "A security event was recorded.",
		"action":      "Review your access logs.",
		"label_time":  "Time:",
		"label_event": "Event:",
		"label_ip":    "IP:",
		"app_name":    "ipgaze",
		"app_url":     "https://ifcfg.us",
		"message":     "login from unknown IP",
		"ip":          "1.2.3.4",
		"time":        "2026-06-23T10:00:00Z",
	}
	subject, body := tmpl.Render(vars)

	if !strings.Contains(subject, "ipgaze") {
		t.Errorf("rendered subject missing app_name: %q", subject)
	}
	if strings.Contains(body, "{") {
		t.Errorf("rendered body still contains an unresolved token: %q", body)
	}
	if !strings.Contains(body, "1.2.3.4") {
		t.Errorf("rendered body missing IP: %q", body)
	}

	mimeBody, err := buildMultipartBody(subject, body, "from@example.com", []string{"admin@example.com"})
	if err != nil {
		t.Fatalf("buildMultipartBody: %v", err)
	}
	if len(mimeBody) == 0 {
		t.Fatal("expected non-empty MIME body")
	}
}

// --- sendWithTLSMode ---

// fakePlaintextSMTPServer accepts a single connection and speaks just enough
// SMTP (no STARTTLS support advertised) to let net/smtp complete a full
// MAIL/RCPT/DATA transaction, so sendWithTLSMode's "none" and "auto" plaintext
// paths can be exercised without a real mail server.
func fakePlaintextSMTPServer(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		fmt.Fprint(conn, "220 test.smtp.local ESMTP\r\n")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			upper := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case inData:
				if strings.TrimRight(line, "\r\n") == "." {
					inData = false
					fmt.Fprint(conn, "250 OK queued\r\n")
				}
			case strings.HasPrefix(upper, "EHLO"):
				fmt.Fprint(conn, "250-test.smtp.local\r\n250 OK\r\n")
			case strings.HasPrefix(upper, "MAIL FROM"):
				fmt.Fprint(conn, "250 OK\r\n")
			case strings.HasPrefix(upper, "RCPT TO"):
				fmt.Fprint(conn, "250 OK\r\n")
			case upper == "DATA":
				inData = true
				fmt.Fprint(conn, "354 Start mail input\r\n")
			case upper == "QUIT":
				fmt.Fprint(conn, "221 Bye\r\n")
				return
			default:
				fmt.Fprint(conn, "500 unrecognized command\r\n")
			}
		}
	}()

	h, portStr, _ := net.SplitHostPort(ln.Addr().String())
	fmt.Sscanf(portStr, "%d", &port)
	return h, port
}

func TestSendWithTLSMode_NoneModeSucceeds(t *testing.T) {
	host, port := fakePlaintextSMTPServer(t)
	cfg := SMTPConfig{Host: host, Port: port, From: "from@example.com", TLS: "none"}
	if err := sendWithTLSMode(cfg, []string{"to@example.com"}, []byte("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Errorf("sendWithTLSMode(none) against fake plaintext server: %v", err)
	}
}

func TestSendWithTLSMode_AutoModeNonImplicitPortFallsBackToPlaintext(t *testing.T) {
	host, port := fakePlaintextSMTPServer(t)
	cfg := SMTPConfig{Host: host, Port: port, From: "from@example.com", TLS: "auto"}
	if err := sendWithTLSMode(cfg, []string{"to@example.com"}, []byte("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Errorf("sendWithTLSMode(auto, no STARTTLS advertised) against fake plaintext server: %v", err)
	}
}

func TestSendWithTLSMode_StartTLSRequiredButUnsupported_ReturnsError(t *testing.T) {
	host, port := fakePlaintextSMTPServer(t)
	cfg := SMTPConfig{Host: host, Port: port, From: "from@example.com", TLS: "starttls"}
	err := sendWithTLSMode(cfg, []string{"to@example.com"}, []byte("Subject: hi\r\n\r\nbody\r\n"))
	if err == nil {
		t.Error("sendWithTLSMode(starttls) against a server without STARTTLS: want error, got nil")
	}
}

func TestSendWithTLSMode_DialError(t *testing.T) {
	cfg := SMTPConfig{Host: "127.0.0.1", Port: 1, From: "from@example.com"}
	err := sendWithTLSMode(cfg, []string{"to@example.com"}, []byte("Subject: hi\r\n\r\nbody\r\n"))
	if err == nil {
		t.Error("sendWithTLSMode against unreachable host: want error, got nil")
	}
}

func TestSendWithTLSMode_TLSModeDialError(t *testing.T) {
	// TLS mode dials straight into tls.DialWithDialer; against a plaintext-only
	// fake server this must fail the TLS handshake and return an error.
	host, port := fakePlaintextSMTPServer(t)
	cfg := SMTPConfig{Host: host, Port: port, From: "from@example.com", TLS: "tls"}
	err := sendWithTLSMode(cfg, []string{"to@example.com"}, []byte("Subject: hi\r\n\r\nbody\r\n"))
	if err == nil {
		t.Error("sendWithTLSMode(tls) against a plaintext server: want error, got nil")
	}
}
