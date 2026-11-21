package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/apimgr/ipgaze/src/tor"

	"github.com/apimgr/ipgaze/src/common/updatechannel"

	"github.com/apimgr/ipgaze/src/paths"
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
// newer nightly published under the devel channel's rolling "devel" tag.
func CheckForUpdate(ctx context.Context, currentVersion, branch string, buildEpoch int64) (*Release, error) {
	if canonical, ok := updatechannel.Normalize(branch); ok {
		branch = canonical
	} else {
		branch = "stable"
	}
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

	client := tor.NewHTTPClient(apiRequestTimeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

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
		if r.TagName == "devel" {
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

// CheckForScheduledUpdate selects the newest eligible release newer than the
// running version. Unlike the manual check, the scheduler must skip a recent
// release and continue looking for an older release that has cleared the
// configured defer window.
func CheckForScheduledUpdate(ctx context.Context, currentVersion, branch string, buildEpoch int64, deferDays int) (*Release, error) {
	if canonical, ok := updatechannel.Normalize(branch); ok {
		branch = canonical
	} else {
		branch = "stable"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubReleasesAll, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := tor.NewHTTPClient(apiRequestTimeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API error: %d", resp.StatusCode)
	}
	var releases []Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&releases); err != nil {
		return nil, err
	}
	for i := range releases {
		release := &releases[i]
		if !matchesBranch(*release, branch) {
			continue
		}
		if release.TagName == "devel" {
			if publishedAfter(release, buildEpoch) {
				return release, nil
			}
			continue
		}
		if release.TagName == currentVersion || strings.TrimPrefix(release.TagName, "v") == currentVersion {
			return nil, nil
		}
		if IsEligible(*release, deferDays) {
			return release, nil
		}
	}
	return nil, nil
}

// DoUpdate downloads the release binary, verifies its SHA-256 checksum, and
// atomically replaces the running binary. The caller is responsible for
// restarting the process (RestartSelf) afterwards.
func DoUpdate(ctx context.Context, release *Release) (retErr error) {
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

	client := tor.NewHTTPClient(binaryDownloadTimeout)

	// Fetch expected SHA-256 from the release's sha256.txt asset — abort if
	// unavailable. Per AI.md PART 22 the checksum is published as a single
	// sha256.txt asset with "{sha256}  {filename}" lines (MANDATORY).
	expectedSum, err := fetchExpectedChecksum(ctx, client, release, assetName)
	if err != nil {
		return fmt.Errorf("failed to fetch checksum: %w", err)
	}

	// Download new binary to temp file while simultaneously hashing.
	tmpDir, err := paths.CreateProjectTempDir()
	if err != nil {
		return fmt.Errorf("cannot create update temp directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary update directory: %w", err))
		}
	}()

	tmpFile, err := os.CreateTemp(tmpDir, "ipgaze-update-*")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary update file: %w", err))
		}
	}()

	dlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return errors.Join(err, tmpFile.Close())
	}
	dlResp, err := client.Do(dlReq)
	if err != nil {
		return errors.Join(fmt.Errorf("download failed: %w", err), tmpFile.Close())
	}
	defer func() {
		if err := dlResp.Body.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close downloaded response: %w", err))
		}
	}()
	if dlResp.StatusCode != http.StatusOK {
		return errors.Join(fmt.Errorf("download HTTP %d", dlResp.StatusCode), tmpFile.Close())
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmpFile, h), dlResp.Body); err != nil {
		return errors.Join(fmt.Errorf("write failed: %w", err), tmpFile.Close())
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temporary update file: %w", err)
	}

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

// StageUpdate downloads a verified release into dataDir/update for the root
// startup phase to install. The running executable is never modified here.
func StageUpdate(ctx context.Context, release *Release, dataDir string) (string, error) {
	assetName := getBinaryName()
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return "", fmt.Errorf("no binary asset found for %s/%s (want %q)", runtime.GOOS, runtime.GOARCH, assetName)
	}
	client := tor.NewHTTPClient(binaryDownloadTimeout)
	expectedSum, err := fetchExpectedChecksum(ctx, client, release, assetName)
	if err != nil {
		return "", fmt.Errorf("failed to fetch checksum: %w", err)
	}
	tmpDir, err := paths.CreateProjectTempDir()
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	tmpBinary := filepath.Join(tmpDir, "ipgaze.new")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download HTTP %d", response.StatusCode)
	}
	file, err := os.OpenFile(tmpBinary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(file, hash), response.Body)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	actualSum := hex.EncodeToString(hash.Sum(nil))
	if actualSum != expectedSum {
		return "", fmt.Errorf("checksum mismatch: expected %s got %s", expectedSum, actualSum)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpBinary, 0o755); err != nil {
			return "", err
		}
	}
	updateDir := filepath.Join(dataDir, "update")
	if info, err := os.Lstat(updateDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("update staging path is not a directory")
		}
		if err := os.RemoveAll(updateDir); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(updateDir, 0o700); err != nil {
		return "", err
	}
	for name, contents := range map[string][]byte{
		"ipgaze.sha256":  []byte(actualSum + "\n"),
		"ipgaze.version": []byte(strings.TrimPrefix(release.TagName, "v") + "\n" + release.PublishedAt + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(updateDir, name), contents, 0o600); err != nil {
			_ = os.RemoveAll(updateDir)
			return "", err
		}
	}
	if err := os.Rename(tmpBinary, filepath.Join(updateDir, "ipgaze.new")); err != nil {
		_ = os.RemoveAll(updateDir)
		return "", err
	}
	return strings.TrimPrefix(release.TagName, "v"), nil
}

// ApplyStagedUpdate verifies and installs a staged update. It returns false
// when no staged binary exists. On success it re-executes the new program.
func ApplyStagedUpdate(dataDir, currentVersion string, currentBuildEpoch int64) (bool, error) {
	updateDir := filepath.Join(dataDir, "update")
	if _, err := os.Lstat(filepath.Join(updateDir, "ipgaze.new")); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	stagedVersion := StagedVersion(dataDir)
	_, err := verifyStagedUpdate(dataDir, currentVersion, currentBuildEpoch)
	if err != nil {
		return false, err
	}
	if stagedVersion == "" || stagedVersion != StagedVersion(dataDir) {
		return false, errors.New("staged update version changed during verification")
	}
	currentPath, err := os.Executable()
	if err != nil {
		return false, err
	}
	currentPath, err = filepath.EvalSymlinks(currentPath)
	if err != nil {
		return false, err
	}
	replacementDir, err := createProtectedReplacementDir(currentPath)
	if err != nil {
		return false, err
	}
	defer func() { _ = os.RemoveAll(replacementDir) }()
	verifiedBinary, err := copyTrustedStagedBinary(dataDir, stagedVersion, currentVersion, currentBuildEpoch, replacementDir)
	if err != nil {
		return false, err
	}
	if err := replaceBinary(currentPath, verifiedBinary); err != nil {
		return false, err
	}
	if err := os.RemoveAll(updateDir); err != nil {
		return false, err
	}
	return true, restartSelf()
}

// copyTrustedStagedBinary copies staged bytes into an owner-only temp directory
// and validates that exact copy against the checksum published by GitHub.
func copyTrustedStagedBinary(dataDir, version, currentVersion string, currentBuildEpoch int64, replacementDir string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout*2)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, githubReleasesAll, nil)
	if err != nil {
		return "", errors.New("cannot verify staged update against published release")
	}
	request.Header.Set("Accept", "application/vnd.github.v3+json")
	client := tor.NewHTTPClient(apiRequestTimeout)
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("cannot verify staged update against published release")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("cannot verify staged update against published release")
	}
	var releases []Release
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&releases); err != nil {
		return "", errors.New("cannot verify staged update against published release")
	}
	var release *Release
	for i := range releases {
		if strings.TrimPrefix(releases[i].TagName, "v") == strings.TrimPrefix(version, "v") {
			release = &releases[i]
			break
		}
	}
	if release == nil {
		return "", errors.New("staged update version is not a published release")
	}
	if !isNewerVersion(version, currentVersion, []string{version, release.PublishedAt}, currentBuildEpoch) {
		return "", errors.New("staged update version is not newer than the running version")
	}
	expected, err := fetchExpectedChecksum(ctx, client, release, getBinaryName())
	if err != nil {
		return "", errors.New("cannot verify staged update against published release checksum")
	}
	source, err := os.Open(filepath.Join(dataDir, "update", "ipgaze.new"))
	if err != nil {
		return "", errors.New("cannot read staged update binary")
	}
	defer func() { _ = source.Close() }()
	destinationPath := filepath.Join(replacementDir, "ipgaze.verified")
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return "", errors.New("cannot create protected update copy")
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(destination, hash), source)
	closeErr := destination.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		_ = os.Remove(destinationPath)
		return "", errors.New("cannot copy staged update binary")
	}
	actual := hash.Sum(nil)
	if !strings.EqualFold(expected, hex.EncodeToString(actual[:])) {
		_ = os.Remove(destinationPath)
		return "", errors.New("staged update does not match the published release checksum")
	}
	return destinationPath, nil
}

// StagedVersion returns the staged release version when its metadata is a
// regular file; an empty string means no trustworthy version is available.
func StagedVersion(dataDir string) string {
	path := filepath.Join(dataDir, "update", "ipgaze.version")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.SplitN(strings.TrimSpace(string(contents)), "\n", 2)
	return strings.TrimSpace(lines[0])
}

func verifyStagedUpdate(dataDir, currentVersion string, currentBuildEpoch int64) (string, error) {
	updateDir := filepath.Join(dataDir, "update")
	newBinary := filepath.Join(updateDir, "ipgaze.new")
	info, err := os.Lstat(updateDir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("staged update path is not a directory")
	}
	for _, name := range []string{"ipgaze.new", "ipgaze.version", "ipgaze.sha256"} {
		fileInfo, statErr := os.Lstat(filepath.Join(updateDir, name))
		if statErr != nil {
			return "", statErr
		}
		if !fileInfo.Mode().IsRegular() {
			return "", fmt.Errorf("staged update file %s is not regular", name)
		}
	}
	versionBytes, err := os.ReadFile(filepath.Join(updateDir, "ipgaze.version"))
	if err != nil {
		return "", err
	}
	versionLines := strings.SplitN(strings.TrimSpace(string(versionBytes)), "\n", 2)
	version := strings.TrimSpace(versionLines[0])
	if version == "" || !isNewerVersion(version, currentVersion, versionLines, currentBuildEpoch) {
		return "", fmt.Errorf("staged version %q is not newer than %q", version, currentVersion)
	}
	expectedBytes, err := os.ReadFile(filepath.Join(updateDir, "ipgaze.sha256"))
	if err != nil {
		return "", err
	}
	expected := strings.TrimSpace(string(expectedBytes))
	contents, err := os.ReadFile(newBinary)
	if err != nil {
		return "", err
	}
	actual := sha256.Sum256(contents)
	if !strings.EqualFold(expected, hex.EncodeToString(actual[:])) {
		return "", errors.New("staged update checksum mismatch")
	}
	return newBinary, nil
}

func isNewerVersion(candidate, current string, versionLines []string, currentBuildEpoch int64) bool {
	candidate = strings.TrimPrefix(candidate, "v")
	current = strings.TrimPrefix(current, "v")
	if current == "devel" {
		if candidate != "devel" || len(versionLines) != 2 || currentBuildEpoch <= 0 {
			return false
		}
		published, err := time.Parse(time.RFC3339, strings.TrimSpace(versionLines[1]))
		return err == nil && published.Unix() > currentBuildEpoch
	}
	candidate, _, _ = strings.Cut(candidate, "+")
	current, _, _ = strings.Cut(current, "+")
	candidateCore, candidatePre, _ := strings.Cut(candidate, "-")
	currentCore, currentPre, _ := strings.Cut(current, "-")
	candidateParts := strings.Split(candidateCore, ".")
	currentParts := strings.Split(currentCore, ".")
	if len(candidateParts) != 3 || len(currentParts) != 3 {
		return false
	}
	for index := range candidateParts {
		candidatePart, candidateErr := strconv.ParseUint(candidateParts[index], 10, 64)
		currentPart, currentErr := strconv.ParseUint(currentParts[index], 10, 64)
		if candidateErr != nil || currentErr != nil {
			return false
		}
		if candidatePart != currentPart {
			return candidatePart > currentPart
		}
	}
	if currentPre == "" {
		return false
	}
	if candidatePre == "" {
		return true
	}
	if candidatePre == currentPre {
		return false
	}
	candidateIDs := strings.Split(candidatePre, ".")
	currentIDs := strings.Split(currentPre, ".")
	for index := 0; index < len(candidateIDs) && index < len(currentIDs); index++ {
		candidateID, currentID := candidateIDs[index], currentIDs[index]
		candidateNumber, candidateErr := strconv.ParseUint(candidateID, 10, 64)
		currentNumber, currentErr := strconv.ParseUint(currentID, 10, 64)
		switch {
		case candidateErr == nil && currentErr == nil:
			if candidateNumber != currentNumber {
				return candidateNumber > currentNumber
			}
		case candidateErr == nil:
			return false
		case currentErr == nil:
			return true
		case candidateID != currentID:
			return candidateID > currentID
		}
	}
	return len(candidateIDs) > len(currentIDs)
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
	defer func() { _ = resp.Body.Close() }()
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
		return false
	}
	published, err := time.Parse(time.RFC3339, r.PublishedAt)
	if err != nil {
		return false
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
// Channels are cumulative: devel ⊇ beta ⊇ stable.
func matchesBranch(r Release, branch string) bool {
	if canonical, ok := updatechannel.Normalize(branch); ok {
		branch = canonical
	} else {
		branch = "stable"
	}
	isBeta := strings.HasSuffix(r.TagName, "-beta")
	isDevel := r.TagName == "devel"
	isStable := !r.Prerelease && !isDevel
	switch branch {
	case "stable":
		return isStable
	case "beta":
		return isStable || isBeta
	case "devel":
		return isStable || isBeta || isDevel
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

// RestartServiceDeferred queues a service restart without waiting for the
// current service process to stop. Scheduled tasks use this to let their
// scheduler job return before the service manager begins shutdown.
func RestartServiceDeferred(userService bool) error {
	return restartServiceDeferred(userService)
}
