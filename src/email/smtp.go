package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProbeResult holds the result of a successful SMTP probe.
type ProbeResult struct {
	Host string
	Port int
}

// smtpCandidates returns the ordered list of hosts to probe per AI.md PART 17.
// Gateway, FQDN, and global IPv4 candidates are filled in by the caller.
func smtpCandidates(gatewayIP, fqdn, globalIPv4 string) []string {
	candidates := []string{
		"127.0.0.1",
		"172.17.0.1",
	}
	if gatewayIP != "" {
		candidates = append(candidates, gatewayIP)
	}
	if fqdn != "" && fqdn != "localhost" {
		candidates = append(candidates, fqdn)
	}
	if globalIPv4 != "" {
		candidates = append(candidates, globalIPv4)
	}
	if fqdn != "" && fqdn != "localhost" {
		candidates = append(candidates, "mail."+fqdn, "smtp."+fqdn)
	}
	return candidates
}

// probeSMTPPort attempts an SMTP EHLO handshake on host:port.
// Returns nil on success.
func probeSMTPPort(host string, port int) error {
	return probeSMTP(SMTPConfig{Host: host, Port: port, TLS: "auto"})
}

func probeSMTP(cfg SMTPConfig) error {
	c, err := openSMTPClient(cfg, 3*time.Second)
	if err != nil {
		return err
	}
	return c.Quit()
}

// AutoDetectSMTP probes candidate hosts for a reachable SMTP server.
// gatewayIP, fqdn, and globalIPv4 are optional hints from the runtime
// environment. Returns the first reachable host+port, or an error if none
// found.
func AutoDetectSMTP(gatewayIP, fqdn, globalIPv4 string) (*ProbeResult, error) {
	ports := []int{25, 465, 587}
	for _, host := range smtpCandidates(gatewayIP, fqdn, globalIPv4) {
		for _, port := range ports {
			if err := probeSMTP(SMTPConfig{Host: host, Port: port, TLS: "auto"}); err == nil {
				return &ProbeResult{Host: host, Port: port}, nil
			}
		}
	}
	return nil, fmt.Errorf("no reachable SMTP server found")
}

// TestConnection verifies the configured SMTP TLS policy and EHLO handshake.
func TestConnection(cfg SMTPConfig) error {
	logPrivateSMTPTLSNotice(cfg)
	return probeSMTP(cfg)
}

func logPrivateSMTPTLSNotice(cfg SMTPConfig) {
	if normalizedTLSMode(cfg.TLS) == "none" || !isPrivateIPLiteral(cfg.Host) {
		return
	}
	log.Printf("SMTP host %s is a private address: TLS certificate verification skipped", cfg.Host)
}

func isPrivateIPLiteral(host string) bool {
	address := host
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = address[1 : len(address)-1]
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	sharedAddressSpace := netip.MustParsePrefix("100.64.0.0/10")
	return ip.Is4() && sharedAddressSpace.Contains(ip)
}

func smtpTLSConfig(host string) *tls.Config {
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if isPrivateIPLiteral(host) {
		// Private literal relays commonly use certificates without IP SANs.
		// This exception is keyed only by the configured literal, never DNS.
		config.InsecureSkipVerify = true //nolint:gosec
	}
	return config
}

func normalizedTLSMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "auto"
	}
	return mode
}

func usesImplicitTLS(cfg SMTPConfig) bool {
	mode := normalizedTLSMode(cfg.TLS)
	return mode == "tls" || mode == "auto" && cfg.Port == 465
}

func openSMTPClient(cfg SMTPConfig, timeout time.Duration) (*smtp.Client, error) {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if usesImplicitTLS(cfg) {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, smtpTLSConfig(cfg.Host))
	} else {
		conn, err = dialer.DialContext(context.Background(), "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("email: dial: %w", err)
	}
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("email: new client: %w", err), conn.Close())
	}
	if err := client.Hello("localhost"); err != nil {
		return nil, errors.Join(fmt.Errorf("email: EHLO: %w", err), client.Close())
	}

	mode := normalizedTLSMode(cfg.TLS)
	if mode == "starttls" || mode == "auto" && cfg.Port != 465 {
		supported, _ := client.Extension("STARTTLS")
		if supported {
			if err := client.StartTLS(smtpTLSConfig(cfg.Host)); err != nil {
				return nil, errors.Join(fmt.Errorf("email: starttls: %w", err), client.Close())
			}
		} else if mode == "starttls" {
			return nil, errors.Join(errors.New("email: server does not support STARTTLS"), client.Close())
		} else if cfg.Username != "" || cfg.Password != "" {
			return nil, errors.Join(errors.New("email: server does not support STARTTLS; refusing cleartext with credentials"), client.Close())
		}
	}
	return client, nil
}

// ApplyEnvOverrides copies SMTP_* env vars onto cfg in place.
// Env vars override config file settings (AI.md PART 17).
func ApplyEnvOverrides(cfg *SMTPConfig) {
	if v := os.Getenv("SMTP_HOST"); v != "" {
		cfg.Host = v
	}
	if v := os.Getenv("SMTP_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			cfg.Port = p
		}
	}
	if v := os.Getenv("SMTP_USERNAME"); v != "" {
		cfg.Username = v
	}
	if v := os.Getenv("SMTP_PASSWORD"); v != "" {
		cfg.Password = v
	}
	// TLS mode: auto | starttls | tls | none (AI.md PART 17).
	if v := os.Getenv("SMTP_TLS"); v != "" {
		cfg.TLS = v
	}
	// SMTP_FROM_EMAIL is the spec name (AI.md PART 17 → from.email);
	// SMTP_FROM is accepted as a backward-compatible alias.
	if v := os.Getenv("SMTP_FROM_EMAIL"); v != "" {
		cfg.From = v
	} else if v := os.Getenv("SMTP_FROM"); v != "" {
		cfg.From = v
	}
	// SMTP_FROM_NAME sets the From header display name (AI.md PART 17 → from.name).
	if v := os.Getenv("SMTP_FROM_NAME"); v != "" {
		cfg.FromName = v
	}
}
