// Package db provides libSQL/Turso remote database support per AI.md PART 10.
// This file wires the tursodatabase/libsql-client-go driver for remote Turso/sqld databases.
// It is a REMOTE-ONLY driver; local SQLite files use modernc.org/sqlite instead.
package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	"github.com/tursodatabase/libsql-client-go/libsql"
)

// OpenLibSQL opens a connection to a remote libSQL/Turso database.
// url may be in either of two forms:
//   - libsql://your-db.turso.io?authToken=xxx  (token embedded in URL)
//   - https://your-db.turso.io                 (token passed separately)
//
// When token is non-empty and the URL does not already contain authToken, the
// token is appended as a query parameter before calling sql.Open.
func OpenLibSQL(connURL, token string) (*sql.DB, error) {
	if connURL == "" {
		return nil, fmt.Errorf("libsql driver requires url: use libsql://host?authToken=xxx or https://host with token field")
	}

	connURL = encodeRawLibSQLUserinfo(connURL)
	parsed, err := url.Parse(connURL)
	if err != nil {
		return nil, fmt.Errorf("invalid libsql connection URL; credentials are omitted")
	}
	query := parsed.Query()
	selectedToken := token
	if parsed.User != nil {
		if password, ok := parsed.User.Password(); ok && password != "" {
			selectedToken = password
		} else if username := parsed.User.Username(); username != "" {
			selectedToken = username
		}
		parsed.User = nil
	}
	for key, values := range query {
		if strings.EqualFold(key, "authToken") || strings.EqualFold(key, "token") {
			if len(values) > 0 {
				selectedToken = values[0]
			}
			delete(query, key)
			break
		}
	}
	tlsEnabled := strings.EqualFold(parsed.Scheme, "libsql") || strings.EqualFold(parsed.Scheme, "https")
	tlsOptionSpecified := false
	for key, values := range query {
		switch strings.ToLower(key) {
		case "tls", "encrypt":
			tlsOptionSpecified = true
			if len(values) > 0 {
				tlsEnabled = strings.EqualFold(values[0], "true") || values[0] == "1"
			}
			delete(query, key)
		case "sslmode":
			tlsOptionSpecified = true
			if len(values) > 0 {
				switch strings.ToLower(values[0]) {
				case "disable":
					tlsEnabled = false
				case "require", "verify-ca", "verify-full":
					tlsEnabled = true
				}
			}
			delete(query, key)
		}
	}
	if strings.EqualFold(parsed.Scheme, "libsql") && tlsOptionSpecified && !tlsEnabled {
		return nil, fmt.Errorf("server.database.url libsql scheme always uses TLS")
	}
	if strings.EqualFold(parsed.Scheme, "https") && tlsOptionSpecified && !tlsEnabled {
		return nil, fmt.Errorf("server.database.url https scheme always uses TLS")
	}
	if strings.EqualFold(parsed.Scheme, "http") && tlsOptionSpecified && tlsEnabled {
		return nil, fmt.Errorf("server.database.url http scheme cannot enable TLS")
	}
	parsed.RawQuery = query.Encode()
	options := []libsql.Option{libsql.WithTls(tlsEnabled)}
	if selectedToken != "" {
		options = append(options, libsql.WithAuthToken(selectedToken))
	}
	return openLibSQLConnector(parsed.String(), options...)
}

func encodeRawLibSQLUserinfo(raw string) string {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return raw
	}
	authorityStart := schemeEnd + 3
	searchFrom := authorityStart
	for searchFrom < len(raw) {
		relativeAt := strings.IndexByte(raw[searchFrom:], '@')
		if relativeAt < 0 {
			return raw
		}
		at := searchFrom + relativeAt
		parsed, err := url.Parse(raw[:authorityStart] + raw[at+1:])
		if err != nil || parsed.Hostname() == "" || parsed.User != nil {
			searchFrom = at + 1
			continue
		}
		userinfo := raw[authorityStart:at]
		username, password, hasPassword := strings.Cut(userinfo, ":")
		encoded := encodeLibSQLUserinfoPart(username)
		if hasPassword {
			encoded += ":" + encodeLibSQLUserinfoPart(password)
		}
		return raw[:authorityStart] + encoded + raw[at:]
	}
	return raw
}

func encodeLibSQLUserinfoPart(raw string) string {
	const hexDigits = "0123456789abcdefABCDEF"
	const hex = "0123456789ABCDEF"
	var encoded strings.Builder
	for index := 0; index < len(raw); index++ {
		value := raw[index]
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("-._~", rune(value)) {
			encoded.WriteByte(value)
			continue
		}
		if value == '%' && index+2 < len(raw) && strings.ContainsRune(hexDigits, rune(raw[index+1])) && strings.ContainsRune(hexDigits, rune(raw[index+2])) {
			encoded.WriteString(raw[index : index+3])
			index += 2
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hex[value>>4])
		encoded.WriteByte(hex[value&0x0f])
	}
	return encoded.String()
}
