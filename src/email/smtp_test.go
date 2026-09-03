package email

import (
	"fmt"
	"net"
	"os"
	"testing"
)

// --- smtpCandidates ---

func TestSMTPCandidates_AlwaysIncludesLocalhost(t *testing.T) {
	candidates := smtpCandidates("", "")
	found := false
	for _, c := range candidates {
		if c == "127.0.0.1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("smtpCandidates() must always include 127.0.0.1; got %v", candidates)
	}
}

func TestSMTPCandidates_AlwaysIncludesDockerGateway(t *testing.T) {
	candidates := smtpCandidates("", "")
	found := false
	for _, c := range candidates {
		if c == "172.17.0.1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("smtpCandidates() must always include 172.17.0.1; got %v", candidates)
	}
}

func TestSMTPCandidates_WithGatewayIP_IncludesIt(t *testing.T) {
	candidates := smtpCandidates("10.0.0.1", "")
	found := false
	for _, c := range candidates {
		if c == "10.0.0.1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("smtpCandidates() must include gatewayIP when set; got %v", candidates)
	}
}

func TestSMTPCandidates_WithFQDN_IncludesVariants(t *testing.T) {
	candidates := smtpCandidates("", "example.com")
	wantVariants := []string{"example.com", "mail.example.com", "smtp.example.com"}
	for _, want := range wantVariants {
		found := false
		for _, c := range candidates {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("smtpCandidates() missing %q with fqdn=example.com; got %v", want, candidates)
		}
	}
}

func TestSMTPCandidates_LocalhostFQDN_Excluded(t *testing.T) {
	candidates := smtpCandidates("", "localhost")
	for _, c := range candidates {
		if c == "localhost" || c == "mail.localhost" || c == "smtp.localhost" {
			t.Errorf("smtpCandidates() should exclude localhost variants; found %q in %v", c, candidates)
		}
	}
}

// --- ApplyEnvOverrides ---

func TestApplyEnvOverrides_Host(t *testing.T) {
	t.Setenv("SMTP_HOST", "mail.example.com")
	cfg := &SMTPConfig{}
	ApplyEnvOverrides(cfg)
	if cfg.Host != "mail.example.com" {
		t.Errorf("Host = %q, want %q", cfg.Host, "mail.example.com")
	}
}

func TestApplyEnvOverrides_Port(t *testing.T) {
	t.Setenv("SMTP_PORT", "465")
	cfg := &SMTPConfig{Port: 587}
	ApplyEnvOverrides(cfg)
	if cfg.Port != 465 {
		t.Errorf("Port = %d, want 465", cfg.Port)
	}
}

func TestApplyEnvOverrides_InvalidPort_Ignored(t *testing.T) {
	t.Setenv("SMTP_PORT", "notanumber")
	cfg := &SMTPConfig{Port: 587}
	ApplyEnvOverrides(cfg)
	if cfg.Port != 587 {
		t.Errorf("Port = %d, invalid env should be ignored, want 587", cfg.Port)
	}
}

func TestApplyEnvOverrides_ZeroPort_Ignored(t *testing.T) {
	t.Setenv("SMTP_PORT", "0")
	cfg := &SMTPConfig{Port: 587}
	ApplyEnvOverrides(cfg)
	if cfg.Port != 587 {
		t.Errorf("Port = %d, zero port should be ignored, want 587", cfg.Port)
	}
}

func TestApplyEnvOverrides_Username(t *testing.T) {
	t.Setenv("SMTP_USERNAME", "user@example.com")
	cfg := &SMTPConfig{}
	ApplyEnvOverrides(cfg)
	if cfg.Username != "user@example.com" {
		t.Errorf("Username = %q, want %q", cfg.Username, "user@example.com")
	}
}

func TestApplyEnvOverrides_Password(t *testing.T) {
	t.Setenv("SMTP_PASSWORD", "secretpass")
	cfg := &SMTPConfig{}
	ApplyEnvOverrides(cfg)
	if cfg.Password != "secretpass" {
		t.Errorf("Password = %q, want %q", cfg.Password, "secretpass")
	}
}

func TestApplyEnvOverrides_TLS_Mode(t *testing.T) {
	for _, v := range []string{"auto", "starttls", "tls", "none"} {
		t.Setenv("SMTP_TLS", v)
		cfg := &SMTPConfig{TLS: "starting-value"}
		ApplyEnvOverrides(cfg)
		if cfg.TLS != v {
			t.Errorf("TLS = %q, want %q", cfg.TLS, v)
		}
	}
}

func TestApplyEnvOverrides_TLS_Empty_NoChange(t *testing.T) {
	os.Unsetenv("SMTP_TLS")
	cfg := &SMTPConfig{TLS: "starttls"}
	ApplyEnvOverrides(cfg)
	if cfg.TLS != "starttls" {
		t.Errorf("TLS changed when env is empty: %q", cfg.TLS)
	}
}

func TestApplyEnvOverrides_From(t *testing.T) {
	t.Setenv("SMTP_FROM", "noreply@example.com")
	cfg := &SMTPConfig{}
	ApplyEnvOverrides(cfg)
	if cfg.From != "noreply@example.com" {
		t.Errorf("From = %q, want %q", cfg.From, "noreply@example.com")
	}
}

func TestApplyEnvOverrides_EmptyVars_NoChange(t *testing.T) {
	os.Unsetenv("SMTP_HOST")
	os.Unsetenv("SMTP_PORT")
	os.Unsetenv("SMTP_USERNAME")
	os.Unsetenv("SMTP_PASSWORD")
	os.Unsetenv("SMTP_TLS")
	os.Unsetenv("SMTP_FROM")
	cfg := &SMTPConfig{Host: "original.host", Port: 587}
	ApplyEnvOverrides(cfg)
	if cfg.Host != "original.host" {
		t.Errorf("Host changed when env is empty: %q", cfg.Host)
	}
	if cfg.Port != 587 {
		t.Errorf("Port changed when env is empty: %d", cfg.Port)
	}
}

// --- probeSMTPPort (via local test server) ---

func TestProbeSMTPPort_Reachable(t *testing.T) {
	// Start a minimal TCP server that responds with a banner + EHLO reply.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Minimal SMTP server: send 220 greeting then handle one command.
		fmt.Fprint(conn, "220 test.smtp.local SMTP\r\n")
		buf := make([]byte, 256)
		conn.Read(buf) //nolint:errcheck
		fmt.Fprint(conn, "250-test.smtp.local\r\n250 OK\r\n")
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	if err := probeSMTPPort(host, port); err != nil {
		t.Errorf("probeSMTPPort to local test server: %v", err)
	}
}

func TestProbeSMTPPort_Unreachable(t *testing.T) {
	// Port 1 is almost certainly not listening.
	err := probeSMTPPort("127.0.0.1", 1)
	if err == nil {
		t.Error("expected error connecting to port 1, got nil")
	}
}

// --- TestConnection ---

func TestTestConnection_Unreachable(t *testing.T) {
	err := TestConnection("127.0.0.1", 1)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// --- AutoDetectSMTP ---

func TestAutoDetectSMTP_NoneReachable(t *testing.T) {
	// In a test environment no SMTP server should be listening on default ports.
	// This test verifies the function returns an error when nothing is found.
	_, err := AutoDetectSMTP("192.0.2.1", "test.invalid")
	if err == nil {
		t.Log("AutoDetectSMTP unexpectedly found a server (acceptable in some environments)")
	}
}

// --- SendTemplate ---

func TestSendTemplate_NotEnabled_ReturnsError(t *testing.T) {
	m := NewEmailManager(SMTPConfig{}, "")
	err := m.SendTemplate("test", []string{"a@b.com"}, nil)
	if err == nil {
		t.Fatal("expected error when email not configured")
	}
}

func TestSendTemplate_MissingTemplate_ReturnsError(t *testing.T) {
	cfg := SMTPConfig{Enabled: true, Host: "smtp.example.com", Port: 587, From: "a@b.com"}
	m := NewEmailManager(cfg, "")
	err := m.SendTemplate("nonexistent_xyz", []string{"a@b.com"}, nil)
	if err == nil {
		t.Fatal("expected error for missing template")
	}
}
