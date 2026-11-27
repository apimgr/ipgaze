package run

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/paths"
)

var (
	Version      = "devel"
	CommitID     = "N/A"
	BuildDate    = "N/A"
	BuildEpoch   = "0"
	OfficialSite = ""
)

// Config is the immutable application configuration plus the run-time seams
// needed by the server lifecycle. A nil Listener means the production bind
// address is used; tests can inject a listener on 127.0.0.1:0.
type Config struct {
	App          *config.AppConfig
	Version      string
	CommitID     string
	BuildDate    string
	BuildEpoch   string
	OfficialSite string
	Listener     net.Listener
	Ready        chan struct{}
	runtime      *serverRuntime
}

type serverRuntime struct {
	httpServer       *http.Server
	httpsServer      *http.Server
	httpHub          *netutil.ListenerHub
	httpsHub         *netutil.ListenerHub
	errChan          <-chan error
	onReady          func()
	onLogReopen      func()
	onStatusDump     func()
	onShutdown       func()
	markShuttingDown func()
	cleanup          func(context.Context) error
	restartRequested <-chan struct{}
}

// ExitCodeError carries a command exit status through the run lifecycle.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("process requested exit status %d", e.Code)
}

func (e *ExitCodeError) Unwrap() error { return e.Err }

// ExitCode returns an explicit status carried by a run error, or fallback.
func ExitCode(err error, fallback int) int {
	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return fallback
}

// ConfigureBuildInfo installs the build metadata embedded by the binary linker.
func ConfigureBuildInfo(version, commitID, buildDate, buildEpochValue, officialSite string) {
	Version = version
	CommitID = commitID
	BuildDate = buildDate
	BuildEpoch = buildEpochValue
	OfficialSite = officialSite
	if epoch := buildEpoch(); epoch > 0 {
		BuildDate = time.Unix(epoch, 0).UTC().Format(time.RFC3339)
	}
}

// BuildConfig loads the operator configuration after main has parsed flags.
func BuildConfig() (*Config, error) {
	dirs := paths.GetDirectories()
	configDir := dirs.Config
	if configDirFlag != nil && *configDirFlag != "" {
		configDir = *configDirFlag
	} else if envConfig := os.Getenv("CONFIG_DIR"); envConfig != "" {
		configDir = envConfig
	}
	safeDir, err := paths.SafeDirPath(configDir)
	if err != nil {
		return nil, fmt.Errorf("invalid config directory: %w", err)
	}
	appConfig, err := config.LoadConfigFromFile(filepath.Join(safeDir, "server.yml"))
	if err != nil {
		if !config.IsRecoverableConfigParseError(err) {
			return nil, fmt.Errorf("load configuration: %w", err)
		}
		log.Printf("Warning: ignoring unparseable config %s/server.yml and using defaults: %v", safeDir, err)
		appConfig = config.DefaultConfig()
	}
	return &Config{
		App:          appConfig,
		Version:      Version,
		CommitID:     CommitID,
		BuildDate:    BuildDate,
		BuildEpoch:   BuildEpoch,
		OfficialSite: OfficialSite,
	}, nil
}

// HandleEarlyFlags handles commands that must not load or create configuration.
func HandleEarlyFlags(binaryName string) bool {
	if showHelp != nil && (*showHelp || *showHelpShort) {
		printHelp(binaryName)
		return true
	}
	if showVersion != nil && (*showVersion || *showVersionShort) {
		fmt.Printf("%s %s\n", binaryName, Version)
		fmt.Printf("Built: %s\n", BuildDate)
		fmt.Printf("Go: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return true
	}
	if shellCmd != nil && *shellCmd != "" {
		if err := handleShellCommand(*shellCmd, binaryName, getLanguage(*langFlag)); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", binaryName, err)
			os.Exit(ExitCode(err, 1))
		}
		return true
	}
	return false
}

// Run executes startup and the production server lifecycle.
func Run(ctx context.Context, cfg *Config) error {
	if cfg == nil || cfg.App == nil {
		return fmt.Errorf("missing application configuration")
	}
	return runPlatform(ctx, cfg)
}

// run starts the same production HTTP servers prepared by startup and owns the
// cancellable serve and graceful-shutdown lifecycle.
func run(ctx context.Context, cfg *Config) error {
	if ctx == nil {
		return fmt.Errorf("missing run context")
	}
	if cfg == nil || cfg.runtime == nil || cfg.runtime.httpServer == nil {
		return fmt.Errorf("missing server runtime")
	}
	runtime := cfg.runtime
	httpListener := cfg.Listener
	if runtime.httpHub != nil {
		httpListener = runtime.httpHub.Listener()
	}
	if httpListener == nil {
		return fmt.Errorf("missing HTTP listener")
	}
	serveErrors := make(chan error, 2)
	go serveHTTP(runtime.httpServer, httpListener, serveErrors, false)
	if runtime.httpsServer != nil {
		if runtime.httpsHub == nil {
			return fmt.Errorf("missing HTTPS listener hub")
		}
		go serveHTTP(runtime.httpsServer, runtime.httpsHub.Listener(), serveErrors, true)
	}
	if runtime.onReady != nil {
		runtime.onReady()
	}
	if cfg.Ready != nil {
		close(cfg.Ready)
	}

	signals := make(chan os.Signal, 1)
	notifyServerSignals(signals)
	defer signal.Stop(signals)
	shutdown := func(cause error) error {
		if runtime.onShutdown != nil {
			runtime.onShutdown()
		}
		if runtime.markShuttingDown != nil {
			runtime.markShuttingDown()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var shutdownErr error
		if runtime.httpsServer != nil {
			if err := runtime.httpsServer.Shutdown(shutdownCtx); err != nil {
				shutdownErr = errors.Join(shutdownErr, fmt.Errorf("shutdown HTTPS server: %w", err))
			}
		}
		if err := runtime.httpServer.Shutdown(shutdownCtx); err != nil {
			shutdownErr = errors.Join(shutdownErr, fmt.Errorf("shutdown HTTP server: %w", err))
		}
		for _, hub := range []*netutil.ListenerHub{runtime.httpsHub, runtime.httpHub} {
			if hub != nil {
				if err := hub.Close(); err != nil && err != net.ErrClosed {
					shutdownErr = errors.Join(shutdownErr, err)
				}
			}
		}
		if runtime.httpHub == nil {
			if err := httpListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				shutdownErr = errors.Join(shutdownErr, err)
			}
		}
		if runtime.cleanup != nil {
			shutdownErr = errors.Join(shutdownErr, runtime.cleanup(shutdownCtx))
		}
		return errors.Join(cause, shutdownErr)
	}

	for {
		select {
		case err := <-serveErrors:
			if err != nil {
				return shutdown(fmt.Errorf("serve HTTP: %w", err))
			}
		case err := <-runtime.errChan:
			if err != nil {
				return shutdown(fmt.Errorf("server runtime: %w", err))
			}
		case <-ctx.Done():
			return shutdown(nil)
		case <-runtime.restartRequested:
			return shutdown(nil)
		case sig := <-signals:
			if isLogReopenSignal(sig) {
				if runtime.onLogReopen != nil {
					runtime.onLogReopen()
				}
				continue
			}
			if isStatusDumpSignal(sig) {
				if runtime.onStatusDump != nil {
					runtime.onStatusDump()
				}
				continue
			}
			return shutdown(nil)
		}
	}
}

func serveHTTP(server *http.Server, listener net.Listener, serveErrors chan<- error, tlsEnabled bool) {
	var err error
	if tlsEnabled {
		err = server.ServeTLS(listener, "", "")
	} else {
		err = server.Serve(listener)
	}
	if err != nil && err != http.ErrServerClosed && err != net.ErrClosed {
		serveErrors <- err
	}
}

// buildEpoch returns the embedded Unix build timestamp, or zero when unset or invalid.
func buildEpoch() int64 {
	epoch, err := strconv.ParseInt(BuildEpoch, 10, 64)
	if err != nil {
		return 0
	}
	return epoch
}
