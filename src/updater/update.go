package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Release represents a GitHub release.
type Release struct {
	TagName     string  `json:"tag_name"`
	Prerelease  bool    `json:"prerelease"`
	PublishedAt string  `json:"published_at"`
	HTMLURL     string  `json:"html_url"`
	Assets      []Asset `json:"assets"`
}

// Asset represents a downloadable release asset.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// githubReleasesLatest and githubReleasesAll are vars so tests can override them.
var (
	githubReleasesLatest = "https://api.github.com/repos/apimgr/ipgaze/releases/latest"
	githubReleasesAll    = "https://api.github.com/repos/apimgr/ipgaze/releases"
)

// apiRequestTimeout bounds the GitHub releases metadata request. It is short
// because it only ever fetches a small JSON payload.
const apiRequestTimeout = 30 * time.Second

// binaryDownloadTimeout bounds the release binary/checksum download. It is
// longer than apiRequestTimeout since it transfers the actual binary, but an
// explicit ceiling still guards against a hung connection blocking the
// updater forever — the caller's ctx remains the primary cancellation path.
const binaryDownloadTimeout = 10 * time.Minute

// CheckForUpdate checks GitHub releases for a newer version.
// Returns nil, nil when already up to date or no matching release found.
// buildEpoch is the caller's own embedded BuildEpoch — needed to detect a
// newer nightly published under the daily channel's rolling "daily" tag.
func CheckForUpdate(ctx context.Context, currentVersion, branch string, buildEpoch int64) (*Release, error) {
	var apiURL string
	switch branch {
	case "stable":
		apiURL = githubReleasesLatest
	default:
		apiURL = githubReleasesAll
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: apiRequestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API error: %d", resp.StatusCode)
	}

	body := io.LimitReader(resp.Body, 4<<20)

	if branch == "stable" {
		var release Release
		if err := json.NewDecoder(body).Decode(&release); err != nil {
			return nil, err
		}
		if release.TagName == currentVersion || strings.TrimPrefix(release.TagName, "v") == currentVersion {
			return nil, nil
		}
		return &release, nil
	}

	var releases []Release
	if err := json.NewDecoder(body).Decode(&releases); err != nil {
		return nil, err
	}

	for i := range releases {
		r := &releases[i]
		if !matchesBranch(*r, branch) {
			continue
		}
		// Rolling tag: the tag name never changes, so a newer nightly exists
		// only when the release was published after this binary was built
		if r.TagName == "daily" {
			if publishedAfter(r, buildEpoch) {
				return r, nil
			}
			continue
		}
		if r.TagName == currentVersion || strings.TrimPrefix(r.TagName, "v") == currentVersion {
			return nil, nil
		}
		return r, nil
	}
	return nil, nil
}

// DoUpdate downloads the release binary, verifies its SHA-256 checksum, and
// atomically replaces the running binary. The caller is responsible for
// restarting the process (RestartSelf) afterwards.
func DoUpdate(ctx context.Context, release *Release) error {
	assetName := getBinaryName()
	var downloadURL string
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("no binary asset found for %s/%s (want %q)", runtime.GOOS, runtime.GOARCH, assetName)
	}

	client := &http.Client{Timeout: binaryDownloadTimeout}

	// Fetch expected SHA-256 from the release's sha256.txt asset — abort if
	// unavailable. Per AI.md PART 22 the checksum is published as a single
	// sha256.txt asset with "{sha256}  {filename}" lines (MANDATORY).
	expectedSum, err := fetchExpectedChecksum(ctx, client, release, assetName)
	if err != nil {
		return fmt.Errorf("failed to fetch checksum: %w", err)
	}

	// Download new binary to temp file while simultaneously hashing.
	tmpFile, err := os.CreateTemp("", "ipgaze-update-*")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	dlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		tmpFile.Close()
		return err
	}
	dlResp, err := client.Do(dlReq)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("download failed: %w", err)
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		tmpFile.Close()
		return fmt.Errorf("download HTTP %d", dlResp.StatusCode)
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmpFile, h), dlResp.Body); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write failed: %w", err)
	}
	tmpFile.Close()

	// Verify checksum before touching the running binary.
	actualSum := hex.EncodeToString(h.Sum(nil))
	if actualSum != expectedSum {
		return fmt.Errorf("checksum mismatch: expected %s got %s — aborting", expectedSum, actualSum)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0755); err != nil {
			return fmt.Errorf("failed to set permissions: %w", err)
		}
	}

	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	currentPath, err = filepath.EvalSymlinks(currentPath)
	if err != nil {
		return fmt.Errorf("cannot resolve symlinks: %w", err)
	}

	return replaceBinary(currentPath, tmpPath)
}

// getBinaryName returns the expected release asset name for the current platform.
func getBinaryName() string {
	name := "ipgaze-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// fetchExpectedChecksum downloads the release's sha256.txt asset and returns
// the lowercase SHA-256 hash recorded for assetName. Per AI.md PART 22 each
// line is "{sha256}  {filename}". Returns an error if the asset is missing or
// has no entry for assetName, so DoUpdate aborts rather than skipping the check.
func fetchExpectedChecksum(ctx context.Context, client *http.Client, release *Release, assetName string) (string, error) {
	var checksumsURL string
	for _, a := range release.Assets {
		if a.Name == "sha256.txt" {
			checksumsURL = a.BrowserDownloadURL
			break
		}
	}
	if checksumsURL == "" {
		return "", fmt.Errorf("release has no sha256.txt asset")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumsURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("checksum fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum download failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("checksum read failed: %w", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == assetName {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %s", assetName)
}

// IsEligible reports whether a release is eligible given a defer_days window.
// Per AI.md PART 22: a release is eligible only once now - published_at >= deferDays.
// deferDays == 0 means immediately eligible; negative values are treated as 0.
func IsEligible(r Release, deferDays int) bool {
	if deferDays <= 0 {
		return true
	}
	if r.PublishedAt == "" {
		return true
	}
	published, err := time.Parse(time.RFC3339, r.PublishedAt)
	if err != nil {
		return true
	}
	return time.Since(published) >= time.Duration(deferDays)*24*time.Hour
}

// publishedAfter reports whether a release was published after the given build
// epoch (Unix seconds, UTC). A zero or unparseable epoch, or a release with no
// published_at, is treated as "not newer" so an unstamped binary never
// re-downloads the same rolling nightly on every check.
func publishedAfter(r *Release, buildEpoch int64) bool {
	if buildEpoch <= 0 || r.PublishedAt == "" {
		return false
	}
	published, err := time.Parse(time.RFC3339, r.PublishedAt)
	if err != nil {
		return false
	}
	return published.Unix() > buildEpoch
}

// matchesBranch reports whether a release belongs to the requested update channel.
// Channels are cumulative: daily ⊇ beta ⊇ stable.
func matchesBranch(r Release, branch string) bool {
	// stable releases match every channel
	if !r.Prerelease {
		return true
	}
	isBeta := strings.HasSuffix(r.TagName, "-beta")
	// The daily channel is a single rolling release: tag "daily", rebuilt nightly
	isDaily := r.TagName == "daily"
	switch branch {
	case "beta":
		return isBeta
	case "daily":
		return isBeta || isDaily
	default:
		return false
	}
}

// RestartSelf re-executes or restarts the process after a successful update.
// On Unix this replaces the current process image via exec(2); on Windows it
// spawns a new process and exits.
func RestartSelf() error {
	return restartSelf()
}

// RestartService restarts the platform service manager entry for ipgaze.
// On Linux it delegates to systemctl; on macOS to launchctl; on Windows to sc.exe.
// Call this instead of RestartSelf when ipgaze is running as a managed service.
func RestartService() error {
	return restartService()
}
