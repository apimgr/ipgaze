package db

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
)

func TestSQLiteDataSourceName(t *testing.T) {
	dbDir := t.TempDir()
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "default", want: filepath.Join(dbDir, "server.db")},
		{name: "bare relative path", url: "custom.db", want: filepath.Join(dbDir, "custom.db")},
		{name: "file relative path", url: "file:custom.db", want: filepath.Join(dbDir, "custom.db")},
		{name: "absolute path", url: filepath.Join(dbDir, "absolute.db"), want: filepath.Join(dbDir, "absolute.db")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := sqliteDataSourceName(test.url, dbDir)
			if err != nil {
				t.Fatalf("sqliteDataSourceName: %v", err)
			}
			if got != test.want {
				t.Errorf("sqliteDataSourceName(%q) = %q, want %q", test.url, got, test.want)
			}
		})
	}
}

func TestEncodeRawLibSQLUserinfo(t *testing.T) {
	password := "pa@ss:/?#[] with space%41%"
	raw := "libsql://db-user:" + password + "@db.example"
	encoded := encodeRawLibSQLUserinfo(raw)
	parsed, err := url.Parse(encoded)
	if err != nil {
		t.Fatalf("url.Parse(encoded connection URL): %v", err)
	}
	if parsed.Hostname() != "db.example" {
		t.Fatalf("hostname = %q, want db.example", parsed.Hostname())
	}
	got, ok := parsed.User.Password()
	if !ok || got != "pa@ss:/?#[] with spaceA%" {
		t.Errorf("parsed password = %q, present = %t; want decoded raw password", got, ok)
	}
}

func TestSQLiteDataSourceNameRejectsKeyValueStrings(t *testing.T) {
	got, err := sqliteDataSourceName("Server=db.example;Password="+strings.Repeat("x", 24), t.TempDir())
	if err == nil {
		t.Fatal("sqliteDataSourceName accepted a key-value connection string")
	}
	if strings.Contains(err.Error(), strings.Repeat("x", 12)) || strings.Contains(got, strings.Repeat("x", 12)) {
		t.Fatal("invalid connection string leaked its credential")
	}
	if !strings.Contains(err.Error(), "use the URL form") {
		t.Errorf("invalid URL error = %q, want URL form guidance", err)
	}
}

func TestNewDB_SQLiteFileURL(t *testing.T) {
	dbDir := t.TempDir()
	cfg := &config.DatabaseConfig{Driver: "sqlite", URL: "file:custom.db"}
	db, err := NewDB(cfg, dbDir)
	if err != nil {
		t.Fatalf("NewDB(file URL): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := os.Stat(filepath.Join(dbDir, "custom.db")); err != nil {
		t.Errorf("SQLite file URL did not create requested database: %v", err)
	}
}

func TestValidateLibSQLURLSchemes(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "libsql TLS", url: "libsql://db.example"},
		{name: "HTTPS TLS", url: "https://db.example"},
		{name: "private HTTP loopback", url: "http://127.0.0.1:8080"},
		{name: "private HTTP RFC1918", url: "http://192.168.1.5:8080"},
		{name: "private HTTP IPv6 ULA", url: "http://[fd00::1]:8080"},
		{name: "public HTTP rejected", url: "http://203.0.113.10", wantErr: true},
		{name: "unsupported JDBC", url: "jdbc:sqlite:db", wantErr: true},
		{name: "malformed URL", url: "https://", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateLibSQLURL(test.url)
			if (err != nil) != test.wantErr {
				t.Errorf("validateLibSQLURL(%q) error = %v, wantErr %t", test.url, err, test.wantErr)
			}
		})
	}
}

func TestLibSQLURLErrorsDoNotExposeCredentials(t *testing.T) {
	secret := strings.Repeat("x", 24)
	err := validateLibSQLURL("javascript://db.example?authToken=" + secret)
	if err == nil {
		t.Fatal("validateLibSQLURL accepted an unsupported scheme")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("URL validation error leaked credential")
	}
}
