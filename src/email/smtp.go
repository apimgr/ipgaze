package email

import (
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"time"
)

// ProbeResult holds the result of a successful SMTP probe.
type ProbeResult struct {
	Host string
	Port int
}

// smtpCandidates returns the ordered list of hosts to probe per AI.md PART 17.
// Gateway and FQDN candidates are filled in by the caller.
func smtpCandidates(gatewayIP, fqdn string) []string {
	candidates := []string{
		"127.0.0.1",
		"172.17.0.1",
	}
	if gatewayIP != "" {
		candidates = append(candidates, gatewayIP)
	}
	if fqdn != "" && fqdn != "localhost" {
		candidates = append(candidates, fqdn, "mail."+fqdn, "smtp."+fqdn)
	}
	return candidates
}

// probeSMTPPort attempts an SMTP EHLO handshake on host:port.
// Returns nil on success.
func probeSMTPPort(host string, port int) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	c.Close()
	return nil
}

// AutoDetectSMTP probes candidate hosts for a reachable SMTP server.
// gatewayIP and fqdn are optional hints from the runtime environment.
// Returns the first reachable host+port, or an error if none found.
func AutoDetectSMTP(gatewayIP, fqdn string) (*ProbeResult, error) {
	ports := []int{587, 465, 25}
	for _, host := range smtpCandidates(gatewayIP, fqdn) {
		for _, port := range ports {
			if err := probeSMTPPort(host, port); err == nil {
				return &ProbeResult{Host: host, Port: port}, nil
			}
		}
	}
	return nil, fmt.Errorf("no reachable SMTP server found")
}

// TestConnection verifies that the given SMTP host:port is reachable.
func TestConnection(host string, port int) error {
	return probeSMTPPort(host, port)
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
