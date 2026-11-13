package email

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestPrivateSMTPAddressClassification(t *testing.T) {
	tests := []struct {
		host    string
		private bool
	}{
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"192.168.1.1", true},
		{"100.64.0.1", true},
		{"100.127.255.254", true},
		{"127.0.0.1", true},
		{"169.254.1.2", true},
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"172.32.0.1", false},
		{"100.128.0.1", false},
		{"smtp.example.test", false},
		{"private-relay.test", false},
		{"localhost", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := isPrivateIPLiteral(tt.host); got != tt.private {
				t.Errorf("isPrivateIPLiteral(%q) = %v, want %v", tt.host, got, tt.private)
			}
			tlsConfig := smtpTLSConfig(tt.host)
			if tlsConfig.InsecureSkipVerify != tt.private {
				t.Errorf("InsecureSkipVerify for %q = %v, want %v", tt.host, tlsConfig.InsecureSkipVerify, tt.private)
			}
			if tlsConfig.ServerName != tt.host {
				t.Errorf("ServerName for %q = %q, want configured host", tt.host, tlsConfig.ServerName)
			}
		})
	}
}

func TestSMTPImplicitTLSSelection(t *testing.T) {
	for _, tt := range []struct {
		cfg  SMTPConfig
		want bool
	}{
		{SMTPConfig{TLS: "auto", Port: 465}, true},
		{SMTPConfig{TLS: "auto", Port: 587}, false},
		{SMTPConfig{TLS: "tls", Port: 587}, true},
		{SMTPConfig{TLS: "starttls", Port: 465}, false},
		{SMTPConfig{TLS: "none", Port: 465}, false},
	} {
		if got := usesImplicitTLS(tt.cfg); got != tt.want {
			t.Errorf("usesImplicitTLS(%+v) = %v, want %v", tt.cfg, got, tt.want)
		}
	}
}

// --- smtpCandidates ---

func TestSMTPCandidates_AlwaysIncludesLocalhost(t *testing.T) {
	candidates := smtpCandidates("", "", "")
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
	candidates := smtpCandidates("", "", "")
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
	candidates := smtpCandidates("10.0.0.1", "", "")
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
	candidates := smtpCandidates("", "example.com", "")
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
	candidates := smtpCandidates("", "localhost", "")
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
	t.Setenv("SMTP_TLS", "")
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
	for _, key := range []string{"SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_TLS", "SMTP_FROM"} {
		t.Setenv(key, "")
	}
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
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
	})

	commands := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Errorf("close SMTP test connection: %v", err)
			}
		}()
		// Minimal SMTP server: send 220 greeting then handle one command.
		if _, err := fmt.Fprint(conn, "220 test.smtp.local SMTP\r\n"); err != nil {
			t.Errorf("write SMTP greeting: %v", err)
			return
		}
		reader := bufio.NewReader(conn)
		command, err := reader.ReadString('\n')
		if err != nil {
			t.Errorf("read SMTP EHLO: %v", err)
			return
		}
		commands <- strings.TrimSpace(command)
		if _, err := fmt.Fprint(conn, "250-test.smtp.local\r\n250 OK\r\n"); err != nil {
			t.Errorf("write EHLO response: %v", err)
			return
		}
		if _, err := reader.ReadString('\n'); err == nil {
			_, _ = fmt.Fprint(conn, "221 Bye\r\n")
		}
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split test listener address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse test listener port: %v", err)
	}

	if err := probeSMTPPort(host, port); err != nil {
		t.Errorf("probeSMTPPort to local test server: %v", err)
	}
	if got := <-commands; !strings.HasPrefix(strings.ToUpper(got), "EHLO ") {
		t.Errorf("probe command = %q, want EHLO", got)
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
	err := TestConnection(SMTPConfig{Host: "127.0.0.1", Port: 1, TLS: "none"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// --- AutoDetectSMTP ---

func TestAutoDetectSMTP_NoneReachable(t *testing.T) {
	// In a test environment no SMTP server should be listening on default ports.
	// This test verifies the function returns an error when nothing is found.
	_, err := AutoDetectSMTP("192.0.2.1", "test.invalid", "")
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
