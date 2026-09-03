//go:build e2e

// Package e2e holds the browser end-to-end suite described in AI.md PART 28
// ("Browser E2E Testing"). It is guarded by the `e2e` build tag so neither
// `go build ./src/...` nor the `make test` commit gate ever compiles it, and
// its only entry point is ./tests/e2e.sh.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// browserUserAgent is a desktop Chrome UA string. The server's content
// negotiation returns plain text to recognized non-interactive HTTP tools
// (curl, wget, Go's default client), so every Tier 1 request that expects
// HTML must present a browser UA.
const browserUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// perTestBrowserTimeout bounds any single browser-driven test so a hung
// navigation fails the run instead of stalling it.
const perTestBrowserTimeout = 90 * time.Second

var (
	// baseURL is the http origin of the server under test, e.g.
	// http://127.0.0.1:64123.
	baseURL string
	// browserEndpoint is the Chrome DevTools HTTP endpoint of the Chromium
	// sidecar, e.g. http://127.0.0.1:9222.
	browserEndpoint string
	// artifactDir receives the server log and any failure artifacts. It
	// always lives under the tempdir structure, never the project tree.
	artifactDir string
)

func TestMain(m *testing.M) {
	code, err := runSuite(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e harness: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// runSuite owns the whole harness lifecycle: it allocates an isolated
// filesystem root and port, starts the real server binary, waits for it to
// answer, runs the tests, then tears everything down. Routing every path
// through one call site keeps the deferred teardown reachable.
func runSuite(m *testing.M) (int, error) {
	binary := os.Getenv("IPGAZE_E2E_BINARY")
	if binary == "" {
		return 0, fmt.Errorf("IPGAZE_E2E_BINARY is not set (run this suite through ./tests/e2e.sh)")
	}
	if _, err := os.Stat(binary); err != nil {
		return 0, fmt.Errorf("server binary %q is not usable: %w", binary, err)
	}

	browserEndpoint = strings.TrimSuffix(os.Getenv("IPGAZE_E2E_BROWSER"), "/")
	if browserEndpoint == "" {
		return 0, fmt.Errorf("IPGAZE_E2E_BROWSER is not set (run this suite through ./tests/e2e.sh)")
	}

	root, err := suiteTempRoot()
	if err != nil {
		return 0, err
	}
	artifactDir = filepath.Join(root, "artifacts")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return 0, err
	}

	port, err := reserveServerPort()
	if err != nil {
		return 0, err
	}
	baseURL = fmt.Sprintf("http://127.0.0.1:%d", port)

	stop, err := startServer(binary, root, port)
	if err != nil {
		return 0, err
	}
	defer stop()

	if err := waitForBrowser(); err != nil {
		return 0, err
	}

	return m.Run(), nil
}

// suiteTempRoot creates the per-run scratch root under the tempdir structure
// mandated by AI.md PART 28 — ${TMPDIR}/{project_org}/{internal_name}-XXXXXX.
func suiteTempRoot() (string, error) {
	if explicit := os.Getenv("IPGAZE_E2E_TMPDIR"); explicit != "" {
		return explicit, os.MkdirAll(explicit, 0o755)
	}
	parent := filepath.Join(os.TempDir(), "apimgr")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, "ipgaze-e2e-")
}

// reserveServerPort picks a free port from the 64000-64999 range AI.md PART 5
// reserves for this project, proving it is bindable before handing it over.
func reserveServerPort() (int, error) {
	source := rand.New(rand.NewSource(time.Now().UnixNano()))
	for attempt := 0; attempt < 200; attempt++ {
		candidate := 64000 + source.Intn(1000)
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", candidate))
		if err != nil {
			continue
		}
		if err := listener.Close(); err != nil {
			continue
		}
		return candidate, nil
	}
	return 0, fmt.Errorf("no free port found in the 64000-64999 range")
}

// startServer launches the compiled server with every directory pointed at
// the run's scratch root, so the suite is hermetic and never touches the
// developer's real config or database. The returned closure terminates the
// process group and is safe to call once.
func startServer(binary, root string, port int) (func(), error) {
	dirs := map[string]string{}
	for _, name := range []string{"config", "data", "cache", "logs", "backups"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(path, 0o755); err != nil {
			return nil, err
		}
		dirs[name] = path
	}

	logPath := filepath.Join(artifactDir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(binary,
		"--config", dirs["config"],
		"--data", dirs["data"],
		"--cache", dirs["cache"],
		"--log", dirs["logs"],
		"--backup", dirs["backups"],
		"--address", "127.0.0.1",
		"--port", fmt.Sprintf("%d", port),
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "MODE=production")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("starting %s: %w", binary, err)
	}

	stop := func() {
		if cmd.Process != nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			done := make(chan struct{})
			go func() {
				cmd.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
		}
		logFile.Close()
	}

	if err := waitForServer(); err != nil {
		stop()
		return nil, fmt.Errorf("%w (server log: %s)", err, logPath)
	}
	return stop, nil
}

// waitForServer polls the health endpoint until the server answers or the
// budget runs out.
func waitForServer() error {
	deadline := time.Now().Add(60 * time.Second)
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		res, err := client.Get(baseURL + "/server/healthz")
		if err == nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("health endpoint returned %d", res.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("server did not become healthy at %s: %v", baseURL, lastErr)
}

// waitForBrowser polls the Chromium sidecar's DevTools endpoint so the first
// browser test does not race the container's startup.
func waitForBrowser() error {
	deadline := time.Now().Add(60 * time.Second)
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		res, err := client.Get(browserEndpoint + "/json/version")
		if err == nil {
			var payload map[string]any
			decodeErr := json.NewDecoder(res.Body).Decode(&payload)
			res.Body.Close()
			if decodeErr == nil && payload["webSocketDebuggerUrl"] != nil {
				return nil
			}
			lastErr = fmt.Errorf("devtools endpoint returned no webSocketDebuggerUrl")
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("chromium sidecar not reachable at %s: %v", browserEndpoint, lastErr)
}

// newBrowserContext opens a fresh tab on the Chromium sidecar. Each test gets
// its own tab so cookies set by one test (theme, lang) never leak into
// another.
func newBrowserContext(t *testing.T) context.Context {
	t.Helper()
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(context.Background(), browserEndpoint)
	tabCtx, cancelTab := chromedp.NewContext(allocCtx)
	timeoutCtx, cancelTimeout := context.WithTimeout(tabCtx, perTestBrowserTimeout)
	t.Cleanup(func() {
		cancelTimeout()
		cancelTab()
		cancelAlloc()
	})
	return timeoutCtx
}

// saveArtifact writes a failure artifact (page HTML, a screenshot) into the
// run's artifact directory and reports where it landed.
func saveArtifact(t *testing.T, name string, content []byte) {
	t.Helper()
	path := filepath.Join(artifactDir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Logf("could not write artifact %s: %v", path, err)
		return
	}
	t.Logf("failure artifact written to %s", path)
}

// browserRequest performs a plain HTTP request that looks like a browser:
// HTML-preferring Accept, English Accept-Language and a desktop Chrome UA.
// Redirects are never followed so status-code assertions stay exact.
func browserRequest(t *testing.T, method, path string, header http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, baseURL+path, nil)
	if err != nil {
		t.Fatalf("building request for %s: %v", path, err)
	}
	req.Header.Set("User-Agent", browserUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	for key, values := range header {
		req.Header.Del(key)
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("requesting %s: %v", path, err)
	}
	return res
}

// getBody fetches a path as a browser would and returns status and body.
func getBody(t *testing.T, path string, header http.Header) (int, string, http.Header) {
	t.Helper()
	res := browserRequest(t, http.MethodGet, path, header)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body of %s: %v", path, err)
	}
	return res.StatusCode, string(body), res.Header
}

// mustContain fails the test when needle is absent from haystack, dumping the
// page to the artifact directory so the failure can be inspected.
func mustContain(t *testing.T, artifact, haystack, needle, what string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		return
	}
	saveArtifact(t, artifact, []byte(haystack))
	t.Errorf("%s: expected to find %q", what, needle)
}
