package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGetBinaryName(t *testing.T) {
	name := getBinaryName()
	if !strings.HasPrefix(name, "ipgaze-") {
		t.Errorf("getBinaryName() = %q; want prefix \"ipgaze-\"", name)
	}
	if !strings.Contains(name, runtime.GOOS) {
		t.Errorf("getBinaryName() = %q; want GOOS %q", name, runtime.GOOS)
	}
	if !strings.Contains(name, runtime.GOARCH) {
		t.Errorf("getBinaryName() = %q; want GOARCH %q", name, runtime.GOARCH)
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(name, ".exe") {
		t.Errorf("getBinaryName() = %q; want .exe suffix on Windows", name)
	}
}

func TestMatchesBranch(t *testing.T) {
	tests := []struct {
		name    string
		release Release
		branch  string
		want    bool
	}{
		{"stable release matches stable", Release{TagName: "v1.2.3", Prerelease: false}, "stable", true},
		{"prerelease excluded from stable", Release{TagName: "v1.2.3-beta", Prerelease: true}, "stable", false},
		{"beta release matches beta", Release{TagName: "v1.2.3-beta", Prerelease: true}, "beta", true},
		{"stable release matches beta (cumulative)", Release{TagName: "v1.2.3", Prerelease: false}, "beta", true},
		{"rolling devel tag matches devel", Release{TagName: "devel", Prerelease: true}, "devel", true},
		{"daily alias matches devel tag", Release{TagName: "devel", Prerelease: true}, "daily", true},
		{"rolling devel tag does not match beta", Release{TagName: "devel", Prerelease: true}, "beta", false},
		{"rolling devel tag does not match stable", Release{TagName: "devel", Prerelease: true}, "stable", false},
		{"beta matches devel (cumulative)", Release{TagName: "v1.2.3-beta", Prerelease: true}, "devel", true},
		{"stable matches devel (cumulative)", Release{TagName: "v1.2.3", Prerelease: false}, "devel", true},
		{"unknown branch acts like stable", Release{TagName: "v1.2.3", Prerelease: false}, "unknown", true},
		{"prerelease excluded from unknown", Release{TagName: "v1.2.3-beta", Prerelease: true}, "unknown", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesBranch(tc.release, tc.branch)
			if got != tc.want {
				t.Errorf("matchesBranch(%+v, %q) = %v; want %v", tc.release, tc.branch, got, tc.want)
			}
		})
	}
}

func TestCheckForUpdateStable_UpToDate(t *testing.T) {
	release := Release{TagName: "v1.0.0", Prerelease: false}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(release); err != nil {
			t.Errorf("encode release response: %v", err)
		}
	}))
	defer srv.Close()

	origLatest := githubReleasesLatest
	githubReleasesLatest = srv.URL
	defer func() { githubReleasesLatest = origLatest }()

	got, err := CheckForUpdate(context.Background(), "1.0.0", "stable", 0)
	if err != nil {
		t.Fatalf("CheckForUpdate error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil (up to date), got %+v", got)
	}
}

func TestCheckForUpdateStable_NewVersion(t *testing.T) {
	release := Release{TagName: "v1.1.0", Prerelease: false}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(release); err != nil {
			t.Errorf("encode release response: %v", err)
		}
	}))
	defer srv.Close()

	origLatest := githubReleasesLatest
	githubReleasesLatest = srv.URL
	defer func() { githubReleasesLatest = origLatest }()

	got, err := CheckForUpdate(context.Background(), "1.0.0", "stable", 0)
	if err != nil {
		t.Fatalf("CheckForUpdate error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a release, got nil")
	}
	if got.TagName != "v1.1.0" {
		t.Errorf("got tag %q; want %q", got.TagName, "v1.1.0")
	}
}

func TestCheckForUpdateDevelChannelDetectsNewNightly(t *testing.T) {
	release := Release{TagName: "devel", Prerelease: true, PublishedAt: time.Now().UTC().Format(time.RFC3339)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode([]Release{release}); err != nil {
			t.Errorf("encode devel release response: %v", err)
		}
	}))
	defer srv.Close()

	origAll := githubReleasesAll
	githubReleasesAll = srv.URL
	defer func() { githubReleasesAll = origAll }()

	got, err := CheckForUpdate(context.Background(), "1.0.0", "daily", time.Now().Add(-24*time.Hour).Unix())
	if err != nil {
		t.Fatalf("CheckForUpdate error: %v", err)
	}
	if got == nil || got.TagName != "devel" {
		t.Fatalf("CheckForUpdate() = %#v, want the newer devel release", got)
	}
}

func TestCheckForUpdateBeta_UpToDate(t *testing.T) {
	releases := []Release{
		{TagName: "v1.0.0-beta", Prerelease: true},
		{TagName: "v0.9.0", Prerelease: false},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(releases); err != nil {
			t.Errorf("encode releases response: %v", err)
		}
	}))
	defer srv.Close()

	origAll := githubReleasesAll
	githubReleasesAll = srv.URL
	defer func() { githubReleasesAll = origAll }()

	got, err := CheckForUpdate(context.Background(), "1.0.0-beta", "beta", 0)
	if err != nil {
		t.Fatalf("CheckForUpdate error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil (up to date), got %+v", got)
	}
}

func TestCheckForUpdateNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	origLatest := githubReleasesLatest
	githubReleasesLatest = srv.URL
	defer func() { githubReleasesLatest = origLatest }()

	got, err := CheckForUpdate(context.Background(), "1.0.0", "stable", 0)
	if err != nil {
		t.Fatalf("CheckForUpdate error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on 404, got %+v", got)
	}
}

func TestCheckForUpdateAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	origLatest := githubReleasesLatest
	githubReleasesLatest = srv.URL
	defer func() { githubReleasesLatest = origLatest }()

	_, err := CheckForUpdate(context.Background(), "1.0.0", "stable", 0)
	if err == nil {
		t.Error("expected error on 500, got nil")
	}
}

func TestIsEligible(t *testing.T) {
	oldTime := time.Now().Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	newTime := time.Now().Add(-1 * 24 * time.Hour).Format(time.RFC3339)

	tests := []struct {
		name      string
		release   Release
		deferDays int
		want      bool
	}{
		{"defer 0 always eligible", Release{PublishedAt: newTime}, 0, true},
		{"negative defer always eligible", Release{PublishedAt: newTime}, -1, true},
		{"old release passes defer window", Release{PublishedAt: oldTime}, 30, true},
		{"new release fails defer window", Release{PublishedAt: newTime}, 30, false},
		{"empty published_at is not eligible", Release{PublishedAt: ""}, 30, false},
		{"invalid published_at is not eligible", Release{PublishedAt: "not-a-date"}, 30, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsEligible(tc.release, tc.deferDays)
			if got != tc.want {
				t.Errorf("IsEligible() = %v, want %v", got, tc.want)
			}
		})
	}
}
