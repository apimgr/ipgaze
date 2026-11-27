package db

import (
	"database/sql/driver"
	"regexp"
	"strings"
)

var legacyTableRenamePattern = regexp.MustCompile(`(?i)^\s*ALTER\s+TABLE\s+([a-z_][a-z0-9_]*)\s+RENAME\s+TO\s+(srv_[a-z_][a-z0-9_]*)\s*;?\s*$`)
var legacyIndexDropPattern = regexp.MustCompile(`(?i)^\s*DROP\s+INDEX\s+([a-z_][a-z0-9_]*)\s*;?\s*$`)

var databaseObjectNames = func() map[string]struct{} {
	names := []string{
		"rate_limits", "audit_log", "scheduler_tasks", "scheduler_history", "backups",
		"owners", "api_tokens", "app_secrets", "app_secrets_legacy", "pgp_keypairs", "ip_blocks",
		"security_reports", "captcha_challenges",
		"idx_rate_limits_window", "idx_audit_timestamp", "idx_audit_category", "idx_audit_actor_ip", "idx_audit_target",
		"idx_scheduler_next_run", "idx_scheduler_enabled", "idx_scheduler_history_task", "idx_scheduler_history_started",
		"idx_backups_created", "idx_api_tokens_primary", "idx_api_tokens_linked_name", "idx_api_tokens_hash",
		"idx_api_tokens_prefix", "idx_api_tokens_public_id", "idx_api_tokens_owner", "idx_api_tokens_active", "idx_pgp_keypairs_revoked",
		"idx_ip_blocks_expiry", "idx_security_reports_public", "idx_captcha_challenges_expires",
	}
	result := make(map[string]struct{}, len(names))
	for _, name := range names {
		result[name] = struct{}{}
	}
	return result
}()

// DatabaseObjectName maps every standard database table and index to its
// canonical backend name. SQLite names are unchanged; remote libSQL objects
// use the required srv_ prefix.
func DatabaseObjectName(driver, name string) string {
	canonical := strings.TrimSpace(name)
	if driver != "libsql" {
		return canonical
	}
	lower := strings.ToLower(canonical)
	if strings.HasPrefix(lower, "srv_") {
		return canonical
	}
	if _, ok := databaseObjectNames[lower]; ok {
		return "srv_" + canonical
	}
	return canonical
}

func mapDatabaseSQL(query string, remote bool) string {
	if !remote || query == "" {
		return query
	}
	if matches := legacyTableRenamePattern.FindStringSubmatch(query); len(matches) == 3 {
		legacy := strings.ToLower(matches[1])
		if _, ok := databaseObjectNames[legacy]; ok && DatabaseObjectName("libsql", matches[1]) == matches[2] {
			return query
		}
	}
	if matches := legacyIndexDropPattern.FindStringSubmatch(query); len(matches) == 2 {
		legacy := strings.ToLower(matches[1])
		if strings.HasPrefix(legacy, "idx_") {
			if _, ok := databaseObjectNames[legacy]; ok {
				return query
			}
		}
	}
	var out strings.Builder
	out.Grow(len(query) + 32)
	for i := 0; i < len(query); {
		ch := query[i]
		if ch == '\'' {
			start := i
			i++
			for i < len(query) {
				if query[i] == '\'' {
					i++
					if i < len(query) && query[i] == '\'' {
						i++
						continue
					}
					break
				}
				i++
			}
			out.WriteString(query[start:i])
			continue
		}
		if ch == '-' && i+1 < len(query) && query[i+1] == '-' {
			start := i
			for i < len(query) && query[i] != '\n' {
				i++
			}
			out.WriteString(query[start:i])
			continue
		}
		if ch == '/' && i+1 < len(query) && query[i+1] == '*' {
			start := i
			i += 2
			for i+1 < len(query) && !(query[i] == '*' && query[i+1] == '/') {
				i++
			}
			if i+1 < len(query) {
				i += 2
			}
			out.WriteString(query[start:i])
			continue
		}
		if ch == '"' || ch == '`' || ch == '[' {
			close := ch
			if ch == '[' {
				close = ']'
			}
			start := i
			i++
			nameStart := i
			for i < len(query) && query[i] != close {
				i++
			}
			name := query[nameStart:i]
			if i < len(query) {
				i++
			}
			out.WriteByte(ch)
			out.WriteString(DatabaseObjectName("libsql", name))
			if i > start && query[i-1] == close {
				out.WriteByte(close)
			}
			continue
		}
		if isSQLWordStart(ch) {
			start := i
			i++
			for i < len(query) && isSQLWordPart(query[i]) {
				i++
			}
			out.WriteString(DatabaseObjectName("libsql", query[start:i]))
			continue
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}

func mapDatabaseArgs(query string, args []driver.NamedValue, remote bool) []driver.NamedValue {
	if !remote || !strings.Contains(strings.ToLower(query), "sqlite_master") {
		return args
	}
	mapped := append([]driver.NamedValue(nil), args...)
	for i := range mapped {
		if name, ok := mapped[i].Value.(string); ok {
			mapped[i].Value = DatabaseObjectName("libsql", name)
		}
	}
	return mapped
}

func isSQLWordStart(ch byte) bool {
	return ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}

func isSQLWordPart(ch byte) bool {
	return isSQLWordStart(ch) || ch >= '0' && ch <= '9'
}
