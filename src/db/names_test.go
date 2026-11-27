package db

import (
	"database/sql/driver"
	"testing"
)

func TestDatabaseObjectName(t *testing.T) {
	tests := []struct {
		name   string
		driver string
		input  string
		want   string
	}{
		{name: "sqlite unchanged", driver: "sqlite", input: "api_tokens", want: "api_tokens"},
		{name: "remote table", driver: "libsql", input: "api_tokens", want: "srv_api_tokens"},
		{name: "remote index", driver: "libsql", input: "idx_api_tokens_hash", want: "srv_idx_api_tokens_hash"},
		{name: "already mapped", driver: "libsql", input: "srv_api_tokens", want: "srv_api_tokens"},
		{name: "unknown unchanged", driver: "libsql", input: "custom_table", want: "custom_table"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DatabaseObjectName(test.driver, test.input); got != test.want {
				t.Fatalf("DatabaseObjectName(%q, %q) = %q, want %q", test.driver, test.input, got, test.want)
			}
		})
	}
}

func TestMapDatabaseSQL(t *testing.T) {
	query := "CREATE TABLE IF NOT EXISTS api_tokens (id TEXT); CREATE INDEX idx_api_tokens_hash ON api_tokens(id); SELECT 'api_tokens' -- api_tokens\nFROM api_tokens"
	want := "CREATE TABLE IF NOT EXISTS srv_api_tokens (id TEXT); CREATE INDEX srv_idx_api_tokens_hash ON srv_api_tokens(id); SELECT 'api_tokens' -- api_tokens\nFROM srv_api_tokens"
	if got := mapDatabaseSQL(query, true); got != want {
		t.Fatalf("mapDatabaseSQL() = %q, want %q", got, want)
	}
	if got := mapDatabaseSQL(query, false); got != query {
		t.Fatalf("mapDatabaseSQL(SQLite) changed query: %q", got)
	}
}

func TestMapDatabaseSQLPreservesLegacyAdoptionSourceNames(t *testing.T) {
	for _, test := range []struct {
		query string
		want  string
	}{
		{query: "ALTER TABLE api_tokens RENAME TO srv_api_tokens", want: "ALTER TABLE api_tokens RENAME TO srv_api_tokens"},
		{query: "DROP INDEX idx_api_tokens_hash", want: "DROP INDEX idx_api_tokens_hash"},
	} {
		if got := mapDatabaseSQL(test.query, true); got != test.want {
			t.Errorf("mapDatabaseSQL(%q) = %q, want %q", test.query, got, test.want)
		}
	}
}

func TestMapDatabaseArgsForSchemaLookup(t *testing.T) {
	args := []driver.NamedValue{{Ordinal: 1, Value: "api_tokens"}, {Ordinal: 2, Value: "ordinary-value"}}
	mapped := mapDatabaseArgs(`SELECT name FROM sqlite_master WHERE name=?`, args, true)
	if got := mapped[0].Value; got != "srv_api_tokens" {
		t.Fatalf("mapped table name = %#v, want srv_api_tokens", got)
	}
	if got := mapped[1].Value; got != "ordinary-value" {
		t.Fatalf("ordinary query argument changed: %#v", got)
	}
	if got := args[0].Value; got != "api_tokens" {
		t.Fatalf("original argument slice mutated: %#v", got)
	}
}
