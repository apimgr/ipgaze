// Package db provides libSQL/Turso remote database support per AI.md PART 10.
// This file wires the tursodatabase/libsql-client-go driver for remote Turso/sqld databases.
// It is a REMOTE-ONLY driver; local SQLite files use modernc.org/sqlite instead.
package db

import (
	"database/sql"
	"fmt"
	"strings"
)

// OpenLibSQL opens a connection to a remote libSQL/Turso database.
// url may be in either of two forms:
//   - libsql://your-db.turso.io?authToken=xxx  (token embedded in URL)
//   - https://your-db.turso.io                 (token passed separately)
//
// When token is non-empty and the URL does not already contain authToken, the
// token is appended as a query parameter before calling sql.Open.
func OpenLibSQL(url, token string) (*sql.DB, error) {
	if url == "" {
		return nil, fmt.Errorf("libsql driver requires url: use libsql://host?authToken=xxx or https://host with token field")
	}

	// Append token as authToken query parameter when provided separately.
	if token != "" && !strings.Contains(url, "authToken=") {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url = url + sep + "authToken=" + token
	}

	return OpenLibSQLDriver(url)
}
