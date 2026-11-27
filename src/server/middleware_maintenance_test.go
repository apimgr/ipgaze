package server

import (
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/db"
	serverhandler "github.com/apimgr/ipgaze/src/server/handler"
)

func TestProbeCriticalSubsystemsTreatsMissingRequiredDatabaseAsFailure(t *testing.T) {
	srv := &Server{HealthHandler: &serverhandler.HealthHandler{DBRequired: true}}

	code, reason, guidance, err := srv.probeCriticalSubsystems()
	if err == nil {
		t.Fatal("probeCriticalSubsystems() error = nil, want required database failure")
	}
	if code != maintenanceCodeDatabase {
		t.Fatalf("maintenance code = %q, want %q", code, maintenanceCodeDatabase)
	}
	if !strings.Contains(reason, "database connection is unavailable") {
		t.Fatalf("maintenance reason = %q, want database connection guidance", reason)
	}
	if !strings.Contains(guidance, "retry the connection automatically") {
		t.Fatalf("maintenance guidance = %q, want automatic retry guidance", guidance)
	}
}

func TestProbeCriticalSubsystemsAllowsUnconfiguredDatabase(t *testing.T) {
	srv := &Server{HealthHandler: &serverhandler.HealthHandler{}}

	code, reason, guidance, err := srv.probeCriticalSubsystems()
	if err != nil || code != "" || reason != "" || guidance != "" {
		t.Fatalf("probeCriticalSubsystems() = (%q, %q, %q, %v), want no failure", code, reason, guidance, err)
	}
}

func TestProbeCriticalSubsystemsRecoversRequiredDatabase(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig().Server.Database
	srv := &Server{HealthHandler: &serverhandler.HealthHandler{DBRequired: true}}
	srv.SetDatabaseRecovery(func() (*db.Store, error) {
		return db.NewDB(&cfg, dir)
	})

	code, reason, guidance, err := srv.probeCriticalSubsystems()
	if err != nil || code != "" || reason != "" || guidance != "" {
		t.Fatalf("probeCriticalSubsystems() = (%q, %q, %q, %v), want recovered", code, reason, guidance, err)
	}
	if srv.database() == nil {
		t.Fatal("database recovery did not attach the recovered database")
	}
	if srv.HealthHandler.DB != srv.database() {
		t.Fatal("database recovery did not update health database")
	}
	if err := srv.database().Close(); err != nil {
		t.Fatalf("close recovered database: %v", err)
	}
}
