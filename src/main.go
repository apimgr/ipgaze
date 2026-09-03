package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/apimgr/ipgaze/src/blocklist"
	"github.com/apimgr/ipgaze/src/cache"
	"github.com/apimgr/ipgaze/src/common/banner"
	"github.com/apimgr/ipgaze/src/common/display"
	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/cve"
	"github.com/apimgr/ipgaze/src/db"
	"github.com/apimgr/ipgaze/src/email"
	"github.com/apimgr/ipgaze/src/geoip"
	gql "github.com/apimgr/ipgaze/src/graphql"
	"github.com/apimgr/ipgaze/src/i2p"
	"github.com/apimgr/ipgaze/src/iputil"
	applog "github.com/apimgr/ipgaze/src/log"
	appmode "github.com/apimgr/ipgaze/src/mode"
	"github.com/apimgr/ipgaze/src/netutil"
	paths "github.com/apimgr/ipgaze/src/path"
	"github.com/apimgr/ipgaze/src/pgp"
	"github.com/apimgr/ipgaze/src/scheduler"
	"github.com/apimgr/ipgaze/src/security"
	"github.com/apimgr/ipgaze/src/server"
	smetrics "github.com/apimgr/ipgaze/src/server/metrics"
	"github.com/apimgr/ipgaze/src/server/model"
	svc "github.com/apimgr/ipgaze/src/service"
	"github.com/apimgr/ipgaze/src/ssl"
	"github.com/apimgr/ipgaze/src/swagger"
	"github.com/apimgr/ipgaze/src/threat"
	"github.com/apimgr/ipgaze/src/tor"
	"github.com/apimgr/ipgaze/src/updater"
	_ "modernc.org/sqlite"
)

// Build info - BuildEpoch is set via -ldflags at build time; BuildDate is derived from it
var (
	Version  = "devel"
	CommitID = "N/A"
	// BuildDate is derived from BuildEpoch in init(); "N/A" when BuildEpoch is unset
	BuildDate = "N/A"
	// BuildEpoch is the Unix build timestamp (seconds, UTC) set via -ldflags; "0" when unset
	BuildEpoch = "0"
	// When empty, users must supply the --server flag
	OfficialSite = ""
)

// buildEpoch parses the embedded BuildEpoch ldflag; 0 when unset or invalid.
// Passed to updater.CheckForUpdate so the daily channel's rolling "daily" tag
// can be compared against this binary's own build time.
func buildEpoch() int64 {
	n, err := strconv.ParseInt(BuildEpoch, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// init derives BuildDate (RFC 3339 UTC) from the embedded BuildEpoch
func init() {
	if n := buildEpoch(); n > 0 {
		BuildDate = time.Unix(n, 0).UTC().Format("2006-01-02T15:04:05Z")
	}
}

const projectName = "ipgaze"

// Query timeout budgets from AI.md PART 10 "Query Timeouts".
const (
	// simpleSelectTimeout bounds a single-table SELECT.
	simpleSelectTimeout = 5 * time.Second
	// writeQueryTimeout bounds an INSERT/UPDATE/DELETE.
	writeQueryTimeout = 10 * time.Second
)

// sysexits — standard POSIX exit codes (from /usr/include/sysexits.h).
// stdlib does not export these; define them locally per go_conventions.md.
const (
	// command line usage error
	exUsage = 64
	// internal software error
	exSoftware = 70
	// system error (e.g., can't fork, mkdir failed)
	exOsErr = 71
	// can't create output file/directory
	exCantCreat = 73
	// input/output error
	exIoErr = 74
	// configuration error
	exConfig = 78
	// permission denied (sysexits.h EX_NOPERM convention)
	exNoPerm = 77
	// generic failure for immediate-exit commands (AI.md PART 30: --update and
	// --status report failure as 1, not a sysexits code)
	exGeneral = 1
)

// defaultTrustedIPHeaders is the standard reverse-proxy client-IP header
// priority list per AI.md PART 12 "Client IP Detection". Applied whenever
// --header is not explicitly set; still gated on trusted_proxies at the
// TrustResolver level, so untrusted peers cannot spoof these headers.
var defaultTrustedIPHeaders = multiValueFlag{
	"CF-Connecting-IP",
	"True-Client-IP",
	"X-Real-IP",
	"X-Forwarded-For",
	"X-Client-IP",
}

type multiValueFlag []string

func (f *multiValueFlag) String() string {
	return strings.Join([]string(*f), ", ")
}

func (f *multiValueFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func init() {
	log.SetPrefix("ipgaze: ")
	log.SetFlags(log.Lshortfile)
}

// resolvePIDFilePath applies the PID file precedence of AI.md PART 7:
// the --pid flag, then the PID_FILE environment variable, then the
// OS default. Both the server startup path and `ipgaze tor ...` use it so
// the CLI locates exactly the PID file the running server wrote.
func resolvePIDFilePath(flagValue, osDefault string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("PID_FILE"); env != "" {
		return env
	}
	return osDefault
}

// writePIDFile writes the current process PID to pidPath.
// Per AI.md PART 26 ("Drop the binary anywhere, run it, everything works" —
// no manual directory creation, no permission fixing): a PID directory that
// isn't writable (e.g. an unwritable bind-mounted /data in Docker) must
// degrade gracefully like config/log/token generation already do elsewhere
// in startup, not crash the whole process. --status/service stop lose PID
// tracking, but the server keeps running.
func writePIDFile(pidPath string) {
	// Containers get no PID file — process management is the orchestrator's job
	// (AI.md PART 8 "PID File Handling"). Skip creation entirely.
	if paths.IsRunningInContainer() {
		return
	}
	if err := paths.WritePIDFile(pidPath); err != nil {
		log.Printf("Warning: Failed to write PID file %s: %v (continuing without PID tracking)", pidPath, err)
	}
}

// removePIDFile removes the PID file if it belongs to the current process.
func removePIDFile(pidPath string) {
	if paths.IsRunningInContainer() {
		return
	}
	_ = paths.RemovePIDFile(pidPath)
}

// checkStalePID checks whether pidPath is stale and removes it if so.
// A stale file is one whose PID no longer refers to a running ipgaze process.
func checkStalePID(pidPath string) {
	// Containers skip PID file checking entirely (AI.md PART 8).
	if paths.IsRunningInContainer() {
		return
	}
	// CheckPIDFile already removes the stale file as a side effect.
	_, _, _ = paths.CheckPIDFile(pidPath)
}

func main() {
	// Get default directories
	dirs := paths.GetDirectories()

	// Flags per AI.md PART 8 - only -h and -v allowed as short flags
	// Short flags
	showHelpShort := flag.Bool("h", false, "Show help")
	showVersionShort := flag.Bool("v", false, "Show version information")

	// Long flags
	port := flag.String("port", "", "Server port (overrides config)")
	address := flag.String("address", "", "Server address (overrides config)")
	dataDir := flag.String("data", "", "Data directory")
	configDirFlag := flag.String("config", "", "Configuration directory")
	cacheDirFlag := flag.String("cache", "", "Cache directory")
	logDirFlag := flag.String("log", "", "Log directory")
	backupDirFlag := flag.String("backup", "", "Backup directory")
	pidFileFlag := flag.String("pid", "", "PID file path")
	baseurlFlag := flag.String("baseurl", "/", "URL path prefix (default: /)")
	showVersion := flag.Bool("version", false, "Show version information")
	showStatus := flag.Bool("status", false, "Check server status (for health checks)")
	showHelp := flag.Bool("help", false, "Show help")
	debugMode := flag.Bool("debug", false, "Enable debug mode")
	daemonMode := flag.Bool("daemon", false, "Run as daemon (detach from terminal)")
	colorMode := flag.String("color", "auto", "Color output: auto, yes, no")
	langFlag := flag.String("lang", "", "Language for output (default: auto-detect from LANG env)")

	// Service commands
	serviceCmd := flag.String("service", "", "Service commands: start, stop, restart, reload, status, --install, --uninstall, --disable, --help")

	// Maintenance commands
	maintenanceCmd := flag.String("maintenance", "", "Maintenance commands: backup, restore, update, mode, setup, pgp, secret, token, data, compliance")

	// Backup content opt-ins (AI.md PART 21) — backups exclude SSL private
	// keys and the full data directory by default (non-credential by default).
	includeSSLFlag := flag.Bool("include-ssl", false, "Include SSL/TLS private keys in backup (default: excluded)")
	includeDataFlag := flag.Bool("include-data", false, "Include full data directory in backup (default: excluded)")

	// Shell commands
	shellCmd := flag.String("shell", "", "Shell integration: completions, init, --help")

	// Mode and update flags
	modeFlag := flag.String("mode", "", "Application mode: production, development")
	updateCmd := flag.String("update", "", "Update commands: check, yes, branch {stable|beta|daily}")

	var headers multiValueFlag
	flag.Var(&headers, "header", "Additional header to trust for remote IP, if present (e.g. X-Real-IP); replaces the default priority list below when set")

	// Per AI.md PART 22 a bare `--update` (no subcommand) is equivalent to
	// `--update yes`. Go's flag package treats `--update` as requiring a value,
	// so inject the default subcommand when `--update`/`-update` appears with no
	// following subcommand (last arg, or followed by another flag).
	for i, arg := range os.Args {
		if arg != "--update" && arg != "-update" {
			continue
		}
		if i == len(os.Args)-1 || strings.HasPrefix(os.Args[i+1], "-") {
			rewritten := make([]string, 0, len(os.Args)+1)
			rewritten = append(rewritten, os.Args[:i+1]...)
			rewritten = append(rewritten, "yes")
			rewritten = append(rewritten, os.Args[i+1:]...)
			os.Args = rewritten
		}
		break
	}
	flag.Parse()

	// Get binary name for user-facing output
	binaryName := filepath.Base(os.Args[0])

	// Handle -h/--help
	if *showHelp || *showHelpShort {
		printHelp(binaryName)
		return
	}

	// Handle -v/--version - format: "ipgaze 1.0.0 (abc123)"
	if *showVersion || *showVersionShort {
		fmt.Printf("%s %s (%s)\n", binaryName, Version, CommitID)
		return
	}

	// Handle --shell command
	if *shellCmd != "" {
		handleShellCommand(*shellCmd, binaryName)
		return
	}

	// Check NO_COLOR and --color flag per AI.md PART 8 — use shared display package
	colorEnabled := display.ColorEnabled(*colorMode)
	_ = colorEnabled

	// Resolve output language per AI.md PART 30 priority chain
	lang := getLanguage(*langFlag)

	// Handle --daemon flag: daemonize before any further setup so the child
	// inherits a clean environment. svc.Daemonize returns nil for the child
	// (which has _DAEMON_CHILD=1 set) and calls os.Exit(0) for the parent.
	if *daemonMode {
		if err := svc.Daemonize(lang); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to daemonize: %v\n", err)
			os.Exit(exOsErr)
		}
	}

	// Handle --debug flag: propagate to env so s.config.IsDebug() works everywhere.
	if *debugMode {
		os.Setenv("DEBUG", "true")
		log.Println("Debug mode enabled")
	}

	// Handle directory overrides from flags per AI.md PART 8.
	// Cache directory: --cache flag > CACHE_DIR env > OS default.
	if *cacheDirFlag != "" {
		dirs.Cache = *cacheDirFlag
	} else if envCache := os.Getenv("CACHE_DIR"); envCache != "" {
		dirs.Cache = envCache
	}
	// Backup directory: --backup flag > BACKUP_DIR env > OS default (AI.md PART 8).
	resolvedBackupDir := paths.GetBackupDir(*backupDirFlag, dirs.Data)

	// Resolve log directory: --log flag > LOG_DIR env > OS default.
	resolvedLogDir := dirs.Logs
	if *logDirFlag != "" {
		resolvedLogDir = *logDirFlag
	} else if envLog := os.Getenv("LOG_DIR"); envLog != "" {
		resolvedLogDir = envLog
	}

	// Config directory: --config flag > CONFIG_DIR env > OS default.
	configDir := dirs.Config
	if *configDirFlag != "" {
		configDir = *configDirFlag
	} else if envConfig := os.Getenv("CONFIG_DIR"); envConfig != "" {
		configDir = envConfig
	}

	// Data directory: --data flag > DATA_DIR env > OS default. Resolved through
	// a local so the DATA_DIR branch is actually reachable — filling the flag
	// value with the OS default first made the env var permanently dead.
	dataDirPath := *dataDir
	if dataDirPath == "" {
		dataDirPath = os.Getenv("DATA_DIR")
	}
	if dataDirPath == "" {
		dataDirPath = dirs.Data
	}
	dataDir = &dataDirPath

	// Fold every resolved override back into dirs so EnsureDirectories creates
	// the directories the operator actually asked for, not only the OS defaults.
	dirs.Config = configDir
	dirs.Data = dataDirPath
	dirs.Logs = resolvedLogDir
	dirs.Backup = resolvedBackupDir

	// Load configuration
	configPath := filepath.Join(configDir, "server.yml")
	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		log.Printf("Warning: Failed to load config: %v, using defaults", err)
		cfg = config.DefaultConfig()
	}

	// Resolve MODE env var per AI.md PART 5 (Runtime env vars re-checked
	// every start, MODE listed explicitly) and PART 6 mode priority
	// (--mode flag > MODE env > default production). MODE must override
	// any persisted server.yml mode on every start, not just first run;
	// the --mode flag block below runs after this and still wins.
	if envMode := os.Getenv("MODE"); envMode != "" {
		if modeErr := applyModeString(cfg, envMode); modeErr != nil {
			log.Printf("Warning: invalid MODE env value %q, ignoring: %v", envMode, modeErr)
		}
	}

	// Block/mutex profiling rates per AI.md PART 6 server.debug.* — gated by
	// the debug flag (--debug/DEBUG=true), never by mode alone. Always set
	// explicitly (including the disabled/0 case) so a prior --debug run in
	// the same process can never leave profiling enabled after a reload.
	if cfg.IsDebug() {
		runtime.SetBlockProfileRate(cfg.Server.Debug.BlockProfileRate)
		runtime.SetMutexProfileFraction(cfg.Server.Debug.MutexProfileFraction)
	} else {
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
	}
	// SQL query logging per AI.md PART 6 server.debug.log_queries — gated by
	// the debug flag, never by mode alone. Must be set before any DB opens.
	db.SetQueryLogging(cfg.IsDebug() && cfg.Server.Debug.LogQueries)

	// Handle --mode flag: an ephemeral per-run override, highest priority in
	// the AI.md PART 6 mode detection chain (flag > MODE env > default). It
	// does NOT persist to server.yml — for a persistent change, use
	// `--maintenance mode <mode>` instead, which requires operator auth.
	if *modeFlag != "" {
		if modeErr := applyModeString(cfg, *modeFlag); modeErr != nil {
			fmt.Printf("Invalid mode: %s\n", *modeFlag)
			fmt.Println("Valid modes: production, development, debug")
			os.Exit(exUsage)
		}
	}

	// Immediate-exit commands run before any privileged startup work per AI.md
	// PART 8: they never serve traffic, so creating directories, provisioning
	// the system user, generating secrets, or daemonizing on their behalf is
	// both wasted work and an unnecessary privileged side effect.

	// Handle --status (health check) against the resolved configured port.
	if *showStatus {
		checkPort, _ := parsePortSpec(resolveServerPort(*port, cfg))
		if checkPort == "" {
			fmt.Fprintln(os.Stderr, "Health check failed: no server port configured")
			os.Exit(exGeneral)
		}
		if err := checkHealth(checkPort); err != nil {
			fmt.Fprintf(os.Stderr, "Health check failed: %v\n", err)
			os.Exit(exGeneral)
		}
		fmt.Println("OK")
		os.Exit(0)
	}

	// Handle --update flag
	if *updateCmd != "" {
		handleUpdateCommand(*updateCmd, cfg)
		return
	}

	// Handle service commands
	if *serviceCmd != "" {
		handleServiceCommand(*serviceCmd, configDir)
		return
	}

	// Handle maintenance commands
	if *maintenanceCmd != "" {
		handleMaintenanceCommand(*maintenanceCmd, configDir, dataDirPath, dirs.Logs, configPath, cfg, *includeSSLFlag, *includeDataFlag)
		return
	}

	// Handle positional subcommands: `ipgaze tor <subcommand>` (AI.md PART 31.1).
	if args := flag.Args(); len(args) >= 1 && args[0] == "tor" {
		handleTorCommand(args[1:], configDir, dataDirPath, dirs.Logs, resolvePIDFilePath(*pidFileFlag, dirs.PID), cfg)
		return
	}

	// Handle positional subcommands: `ipgaze i2p <subcommand>` (AI.md PART 31.2).
	if args := flag.Args(); len(args) >= 1 && args[0] == "i2p" {
		handleI2PCommand(args[1:], configDir, dataDirPath, dirs.Logs, cfg)
		return
	}

	if len(flag.Args()) != 0 {
		flag.Usage()
		return
	}

	// Ensure directories exist. Nothing downstream works without them — config
	// and database writes would fail one by one — so this is fatal, not a warning.
	if err := paths.EnsureDirectories(dirs); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create directories: %v\n", err)
		os.Exit(exCantCreat)
	}

	// Phase 8a/8c: while still root, create the dedicated system user (if
	// missing) and chown all directories to it, per AI.md PART 23 "System
	// User Requirements" and Server Startup Sequence steps 8a/8c. Must run
	// before dropPrivileges below, or the dropped-privilege process cannot
	// write to directories that were just created as root.
	if isElevated() {
		uid, gid, userErr := ensureSystemUser(projectName, dirs.Config)
		if userErr != nil {
			log.Printf("Warning: Failed to create system user %s: %v", projectName, userErr)
		} else {
			for _, d := range []string{dirs.Config, dirs.Data, dirs.Cache, dirs.Logs, dirs.SSL, dirs.Security, dirs.DB, dirs.Backup} {
				if chownErr := chownRecursive(d, uid, gid); chownErr != nil {
					log.Printf("Warning: Failed to set ownership on %s: %v", d, chownErr)
				}
			}
		}
	}

	// Initialize file-based log manager per AI.md PART 11 early, so scheduled
	// tasks registered below (backups, retention, etc.) can write audit events.
	logMgr, logMgrErr := applog.NewManager(resolvedLogDir, buildLogConfig(cfg))
	if logMgrErr != nil {
		log.Printf("Warning: Failed to open log files in %s: %v", resolvedLogDir, logMgrErr)
		logMgr = nil
	} else {
		defer logMgr.Close()
		log.Printf("File-based logging active in %s", resolvedLogDir)
	}

	// Auto-generate operator token on first run per AI.md PART 11.
	// Format: tok_ prefix + 32 URL-safe random base62 chars.
	// The raw token is shown once (startup log) and never retrievable again.
	// The config file is saved immediately so the token persists across restarts.
	if cfg.Server.Token == "" {
		newToken, tokenErr := generateOperatorToken()
		if tokenErr != nil {
			log.Printf("Failed to generate operator token: %v", tokenErr)
			os.Exit(exSoftware)
		}
		cfg.Server.Token = newToken
		if saveErr := config.SaveConfigToFile(); saveErr != nil {
			log.Printf("Warning: Failed to save generated operator token: %v", saveErr)
		}
		log.Printf("Generated operator token: %s (shown once — save it now)", newToken)
	}

	// Auto-generate the AES-256-GCM at-rest encryption key on first run per AI.md
	// PART 11/PART 15. 32 raw bytes, base64-encoded, persisted to server.yml. Used
	// to encrypt sensitive at-rest data such as DNS-01 provider credentials.
	if cfg.Server.Security.EncryptionKey == "" {
		newKey, keyErr := generateEncryptionKey()
		if keyErr != nil {
			log.Printf("Failed to generate encryption key: %v", keyErr)
			os.Exit(exSoftware)
		}
		cfg.Server.Security.EncryptionKey = newKey
		if saveErr := config.SaveConfigToFile(); saveErr != nil {
			log.Printf("Warning: Failed to save generated encryption key: %v", saveErr)
		}
		log.Printf("Generated server encryption key")
	}

	// Validate DNS-01 credentials on startup if configured, per AI.md PART 15.
	if cfg.Server.SSL.LetsEncrypt.DNSProvider != "" && cfg.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted != "" {
		startupSSLMgr := ssl.NewSSLManager(ssl.SSLManagerConfig{
			EncryptionKey: cfg.Server.Security.EncryptionKey,
			LetsEncrypt: ssl.LetsEncryptConfig{
				DNSProvider:             cfg.Server.SSL.LetsEncrypt.DNSProvider,
				DNSCredentialsEncrypted: cfg.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted,
			},
			OnDNSCredentialsValidated: func(validatedAt string) {
				cfg.Server.SSL.LetsEncrypt.DNSCredentials.ValidatedAt = validatedAt
				if saveErr := config.SaveConfigToFile(); saveErr != nil {
					log.Printf("Warning: Failed to save dns_credentials.validated_at: %v", saveErr)
				}
			},
		})
		if err := startupSSLMgr.ValidateDNSCredentials(); err != nil {
			log.Printf("Warning: DNS-01 credential validation failed for provider %q: %v", cfg.Server.SSL.LetsEncrypt.DNSProvider, err)
		} else {
			log.Printf("DNS-01 credentials validated for provider %q", cfg.Server.SSL.LetsEncrypt.DNSProvider)
		}
	}

	// Apply config-based daemonize when --daemon flag was not already provided.
	// svc.ShouldDaemonize respects priority: flag > config > default.
	// This is a no-op for the child process (_DAEMON_CHILD=1 makes Daemonize return nil).
	if !*daemonMode && svc.ShouldDaemonize(false, false, cfg.Server.Daemonize) {
		if err := svc.Daemonize(lang); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to daemonize: %v\n", err)
			os.Exit(exOsErr)
		}
	}

	// Determine port (flag > IPGAZE_PORT > PORT > config).
	// Per AI.md: check {PROJECT_NAME}_PORT (IPGAZE_PORT) first, then generic PORT for container compat.
	serverPort := resolveServerPort(*port, cfg)
	portWasConfigured := serverPort != ""
	if serverPort == "" {
		// Per AI.md PART 12: default port is 80 in a container, otherwise a
		// random unused port in 64000-64999 probed for availability.
		if paths.IsRunningInContainer() {
			serverPort = "80"
		} else {
			serverPort = randomAvailablePort()
		}
	}

	// Determine address (flag > IPGAZE_LISTEN > LISTEN > IPGAZE_ADDRESS > ADDRESS > config > default)
	// Per AI.md PART 5: LISTEN is the canonical env var for listen address.
	// IPGAZE_ADDRESS/ADDRESS are kept as backward-compatible aliases with lower priority.
	serverAddress := cfg.Server.Address
	if *address != "" {
		serverAddress = *address
	} else if envAddr := os.Getenv("IPGAZE_LISTEN"); envAddr != "" {
		serverAddress = envAddr
	} else if envAddr := os.Getenv("LISTEN"); envAddr != "" {
		serverAddress = envAddr
	} else if envAddr := os.Getenv("IPGAZE_ADDRESS"); envAddr != "" {
		serverAddress = envAddr
	} else if envAddr := os.Getenv("ADDRESS"); envAddr != "" {
		serverAddress = envAddr
	}
	if serverAddress == "" {
		serverAddress = "[::]"
	}

	// Split the port setting into its HTTP and HTTPS halves per AI.md PART 12
	// "Dual Port Support": "8090,8443" declares HTTP on 8090 and HTTPS on 8443.
	httpPort, httpsPort := parsePortSpec(serverPort)

	// AI.md PART 12: once selected, the port persists in server.yml. Only the
	// first run picks one at random; every later start reuses the saved value.
	if !portWasConfigured {
		cfg.Server.Port = serverPort
		if saveErr := config.SaveConfigToFile(); saveErr != nil {
			log.Printf("Warning: Failed to persist selected port %s: %v", serverPort, saveErr)
		} else {
			log.Printf("Selected port %s and saved it to %s", serverPort, configPath)
		}
	}

	// Build listen address
	// Per AI.md: [::] binds to all interfaces IPv4/IPv6 (dual-stack)
	listen := listenAddress(serverAddress, httpPort)

	// Log startup information
	log.Printf("ipgaze %s (commit: %s, built: %s)", Version, CommitID, BuildDate)
	log.Println("IPv6 support enabled - server will accept both IPv4 and IPv6 connections")

	// SSL is on when explicitly enabled with an FQDN, or whenever a dual-port
	// spec named a dedicated HTTPS port.
	sslEnabled := (cfg.Server.SSL.Enabled && cfg.Server.FQDN != "") || httpsPort != ""

	// AI.md PART 23 step 4/5: bind every listener while still root, then drop.
	// Binding after the drop makes any port below 1024 fail with EACCES, which
	// is exactly what `--port 80` used to hit.
	httpListenAddr := listen
	httpsListenAddr := ""
	switch {
	case httpsPort != "":
		httpsListenAddr = listenAddress(serverAddress, httpsPort)
	case sslEnabled:
		// Single-port SSL mode serves HTTPS on 443 and redirects from 80.
		httpsListenAddr = listenAddress(serverAddress, "443")
		httpListenAddr = listenAddress(serverAddress, "80")
	}

	httpListener, listenErr := net.Listen("tcp", httpListenAddr)
	if listenErr != nil {
		log.Printf("Failed to bind HTTP listener on %s: %v", httpListenAddr, listenErr)
		os.Exit(exOsErr)
	}
	var httpsListener net.Listener
	if httpsListenAddr != "" {
		httpsListener, listenErr = net.Listen("tcp", httpsListenAddr)
		if listenErr != nil {
			httpListener.Close() //nolint:errcheck
			log.Printf("Failed to bind HTTPS listener on %s: %v", httpsListenAddr, listenErr)
			os.Exit(exOsErr)
		}
	}

	// Phase 7: PID file — atomically check + write per AI.md PART 7.
	// Resolve PID file path: --pid flag > PID_FILE env > OS default (dirs.PID).
	pidFile := resolvePIDFilePath(*pidFileFlag, dirs.PID)
	writePIDFile(pidFile)

	// Phase 8e: initialize and spawn Tor while still privileged, per AI.md
	// PART 23 step 5 — managed children are started before the drop so the
	// root phase owns every privileged action. Scheduler registration for
	// tor_health happens later, once the scheduler itself exists.
	torVirtualPort := cfg.Server.Tor.VirtualPort
	if torVirtualPort == 0 {
		torVirtualPort = 80
	}
	torMgr := tor.NewTorManager(tor.TorServiceConfig{
		ConfigDir:                 configDir,
		DataDir:                   dataDirPath,
		LogDir:                    resolvedLogDir,
		Binary:                    cfg.Server.Tor.Binary,
		UseNetwork:                cfg.Server.Tor.UseNetwork,
		MaxCircuits:               cfg.Server.Tor.MaxCircuits,
		CircuitTimeout:            cfg.Server.Tor.CircuitTimeout,
		BootstrapTimeout:          cfg.Server.Tor.BootstrapTimeout,
		SafeLogging:               cfg.Server.Tor.SafeLogging,
		MaxStreamsPerCircuit:      cfg.Server.Tor.MaxStreamsPerCircuit,
		CloseCircuitOnStreamLimit: cfg.Server.Tor.CloseCircuitOnStreamLimit,
		BandwidthRate:             cfg.Server.Tor.BandwidthRate,
		BandwidthBurst:            cfg.Server.Tor.BandwidthBurst,
		MaxMonthlyBandwidth:       cfg.Server.Tor.MaxMonthlyBandwidth,
		NumIntroPoints:            cfg.Server.Tor.NumIntroPoints,
		VirtualPort:               torVirtualPort,
	})
	torAvailable := torMgr.IsAvailable()
	if torAvailable {
		if err := torMgr.Start(); err != nil {
			log.Printf("Warning: Failed to start Tor: %v", err)
		} else {
			log.Println("Tor hidden service starting (server binary controls Tor per PART 32)")
		}
	} else {
		log.Println("Tor binary not found, hidden service disabled")
	}

	// Phase 8g: Drop privileges (root → ipgaze user) per AI.md PART 23. This is
	// the final root-phase action: directories, listeners, and managed children
	// are all in place. A failed drop means the process would keep running as
	// root, so it fails secure rather than continuing.
	if isElevated() {
		if err := dropPrivileges(projectName); err != nil {
			log.Printf("Failed to drop privileges to user %s: %v", projectName, err)
			removePIDFile(pidFile)
			os.Exit(exNoPerm)
		}
		log.Printf("Dropped privileges to user %s", projectName)
	}

	// Initialize GeoIP manager
	geoMgr := geoip.NewGeoIPManager(*dataDir)
	if err := geoMgr.Initialize(); err != nil {
		log.Printf("Warning: Failed to initialize GeoIP: %v", err)
		log.Println("Server will continue without GeoIP support")
	} else {
		log.Println("GeoIP databases loaded (4 files, ~103MB)")
	}

	// Initialize threat intelligence manager (VPN, proxy, Tor exit-node detection).
	// Files are downloaded on first run; subsequent startups load from disk.
	threatMgr := threat.NewManager(filepath.Join(*dataDir, "security", "threat"), nil)
	threatLookup, err := threatMgr.Initialize()
	if err != nil {
		log.Printf("Warning: threat intelligence init error (detection will be best-effort): %v", err)
	} else {
		log.Println("Threat intelligence lists loaded (VPN/proxy/Tor)")
	}

	// Open server.db per AI.md PART 10: scheduler state persists across restarts.
	// Driver is selected from config: sqlite (default) or libsql/turso (remote).
	var serverDB *sql.DB
	dbDriver := cfg.Server.Database.NormalizedDriver()
	dbCfg := cfg.Server.Database
	if dbDriver == "libsql" {
		// Validate libsql config before attempting connection.
		if valErr := cfg.Server.Database.ValidateLibSQL(); valErr != nil {
			log.Printf("Warning: libsql config invalid, falling back to sqlite: %v", valErr)
			dbDriver = "sqlite"
			dbCfg.Driver = "sqlite"
		}
	}
	// Delegates driver selection, connection pooling, PRAGMA setup, and schema
	// application to db.NewDB so this logic has a single implementation.
	// dirs.DB (not dataDir) is authoritative per PART 4/12: it honors the
	// independently-relocatable DATABASE_DIR env var.
	if dbConn, dbErr := db.NewDB(&dbCfg, dirs.DB); dbErr != nil {
		log.Printf("Warning: Failed to open %s database: %v", dbDriver, dbErr)
	} else {
		serverDB = dbConn
		defer serverDB.Close()
	}

	// Initialize SSL manager per AI.md PART 15.
	// Shared between scheduler renewal task and HTTPS server startup.
	// sslEnabled was resolved before the listeners were bound.
	sslMgr := ssl.NewSSLManager(ssl.SSLManagerConfig{
		Enabled:       sslEnabled,
		CertPath:      filepath.Join(configDir, "ssl"),
		EncryptionKey: cfg.Server.Security.EncryptionKey,
		LetsEncrypt: ssl.LetsEncryptConfig{
			Enabled:                 sslEnabled && cfg.Server.SSL.LetsEncrypt.Enabled,
			Email:                   cfg.Server.SSL.LetsEncrypt.Email,
			Staging:                 cfg.Server.SSL.LetsEncrypt.Staging,
			Challenge:               cfg.Server.SSL.LetsEncrypt.Challenge,
			DNSProvider:             cfg.Server.SSL.LetsEncrypt.DNSProvider,
			DNSCredentialsEncrypted: cfg.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted,
		},
		OnDNSCredentialsValidated: func(validatedAt string) {
			cfg.Server.SSL.LetsEncrypt.DNSCredentials.ValidatedAt = validatedAt
			if saveErr := config.SaveConfigToFile(); saveErr != nil {
				log.Printf("Warning: Failed to save dns_credentials.validated_at: %v", saveErr)
			}
		},
	})
	sslDomains := []string{}
	if cfg.Server.FQDN != "" {
		sslDomains = []string{cfg.Server.FQDN}
	}

	// Initialize email manager per AI.md PART 17.
	// Build SMTPConfig from server.notifications.email; apply env var overrides; auto-detect if no host.
	smtpCfg := email.SMTPConfig{
		Enabled:  cfg.Server.Notifications.Email.Enabled,
		Host:     cfg.Server.Notifications.Email.SMTP.Host,
		Port:     cfg.Server.Notifications.Email.SMTP.Port,
		Username: cfg.Server.Notifications.Email.SMTP.Username,
		Password: cfg.Server.Notifications.Email.SMTP.Password,
		TLS:      cfg.Server.Notifications.Email.SMTP.TLS,
		From:     cfg.Server.Notifications.Email.From.Email,
		FromName: cfg.Server.Notifications.Email.From.Name,
	}
	email.ApplyEnvOverrides(&smtpCfg)
	if smtpCfg.Host == "" {
		if probe, probErr := email.AutoDetectSMTP("", cfg.Server.FQDN); probErr == nil {
			smtpCfg.Host = probe.Host
			smtpCfg.Port = probe.Port
			log.Printf("email: auto-detected SMTP at %s:%d", probe.Host, probe.Port)
		}
	}
	var emailMgr *email.EmailManager
	if smtpCfg.Host != "" {
		if connErr := email.TestConnection(smtpCfg.Host, smtpCfg.Port); connErr == nil {
			smtpCfg.Enabled = true
			emailMgr = email.NewEmailManager(smtpCfg, configDir)
			emailMgr.Start()
			defer emailMgr.Stop()
			log.Printf("email.configured=true smtp=%s:%d", smtpCfg.Host, smtpCfg.Port)
		} else {
			log.Printf("email.configured=false smtp_test_failed=%v", connErr)
		}
	} else {
		log.Println("email.configured=false no_smtp")
	}

	// Initialize the built-in scheduler (AI.md PART 18: always-running, persistent state, catch-up).
	// Backed by go-co-op/gocron/v2 per AI.md PART 3 and PART 18.
	sched, err := scheduler.NewScheduler(serverDB, scheduler.DefaultConfig())
	if err != nil {
		log.Printf("Warning: Failed to initialize scheduler: %v", err)
	} else {
		// AI.md PART 17/18: notify on any scheduled task failure.
		sched.OnFailure = func(task *scheduler.Task, taskErr error) {
			// AI.md PART 17: scheduler_error is suppressed when backup_failed
			// or ssl_renewal_failed already emailed for this same execution.
			alreadyNotified := consumeCriticalTaskEmail(task.ID)
			if emailMgr == nil || !emailMgr.IsEnabled() || !cfg.Server.Notifications.Email.Events.SchedulerError {
				return
			}
			if alreadyNotified {
				log.Printf("scheduler: %s failed — scheduler_error suppressed, a critical event email already went out", task.ID)
				return
			}
			sendOperatorEmail(cfg, emailMgr, "scheduler_error", map[string]string{
				"app_name": projectName,
				"app_url":  cfg.Server.BaseURL,
				"task":     task.Name,
				"error":    taskErr.Error(),
				"time":     time.Now().Format(time.RFC3339),
			})
		}

		// geoip_update: weekly Sunday 03:00 (configurable via server.scheduler.tasks.geoip_update)
		if err := sched.AddTask(&scheduler.Task{
			ID:       "geoip_update",
			Name:     "GeoIP Database Update",
			Schedule: scheduleFor("0 3 * * 0", cfg.Server.Schedule.Tasks.GeoIPUpdate),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.GeoIPUpdate),
			Fn: func() error {
				log.Println("scheduler: running geoip_update")
				return geoMgr.Update()
			},
		}); err != nil {
			log.Printf("Warning: Failed to add geoip_update task: %v", err)
		}
		if err := sched.AddTask(&scheduler.Task{
			ID:       "ssl_renewal",
			Name:     "SSL Certificate Renewal",
			Schedule: scheduleFor("0 3 * * *", cfg.Server.Schedule.Tasks.SSLRenewal),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.SSLRenewal),
			Fn: func() error {
				if len(sslDomains) == 0 {
					return nil
				}
				log.Println("scheduler: running ssl_renewal")
				_, preNotAfter, preOK := sslMgr.CertExpiry(sslDomains)
				wasExpiring := preOK && time.Until(preNotAfter).Hours()/24 <= 7
				renewErr := sslMgr.RenewIfExpiring(sslDomains, 7)
				if renewErr != nil && emailMgr != nil && emailMgr.IsEnabled() && cfg.Server.Notifications.Email.Events.SSLRenewalFailed {
					domain := ""
					if len(sslDomains) > 0 {
						domain = sslDomains[0]
					}
					sendOperatorEmail(cfg, emailMgr, "ssl_renewal_failed", map[string]string{
						"app_name":          projectName,
						"app_url":           cfg.Server.BaseURL,
						"domain":            domain,
						"error":             renewErr.Error(),
						"days_until_expiry": "7",
						"next_retry":        "24h",
					})
					markCriticalTaskEmail("ssl_renewal")
				}
				// AI.md PART 17: only report an expiry-state notification when the
				// cert was actually within the renewal threshold this run —
				// otherwise RenewIfExpiring was a no-op and there's nothing to
				// report. ssl_expiring fires when it's still within the threshold
				// after the attempt (no renewal happened); ssl_renewed fires when
				// it now expires further out (a renewal actually took place).
				if wasExpiring && renewErr == nil && emailMgr != nil && emailMgr.IsEnabled() {
					if fqdn, notAfter, ok := sslMgr.CertExpiry(sslDomains); ok {
						daysLeft := int(time.Until(notAfter).Hours() / 24)
						vars := map[string]string{
							"app_name": projectName,
							"app_url":  cfg.Server.BaseURL,
							"fqdn":     fqdn,
							"expiry":   notAfter.Format("2006-01-02"),
						}
						if daysLeft <= 7 && cfg.Server.Notifications.Email.Events.SSLExpiring {
							vars["days"] = fmt.Sprintf("%d", daysLeft)
							sendOperatorEmail(cfg, emailMgr, "ssl_expiring", vars)
						} else if daysLeft > 7 && cfg.Server.Notifications.Email.Events.SSLRenewed {
							sendOperatorEmail(cfg, emailMgr, "ssl_renewed", vars)
						}
					}
				}
				return renewErr
			},
		}); err != nil {
			log.Printf("Warning: Failed to add ssl_renewal task: %v", err)
		}

		// blocklist_update: daily 04:00 (configurable)
		blMgr := blocklist.NewBlocklistManager(filepath.Join(*dataDir, "security", "blocklists"), nil)
		if err := sched.AddTask(&scheduler.Task{
			ID:       "blocklist_update",
			Name:     "IP Blocklist Update",
			Schedule: scheduleFor("0 4 * * *", cfg.Server.Schedule.Tasks.BlocklistUpdate),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.BlocklistUpdate),
			Fn: func() error {
				log.Println("scheduler: running blocklist_update")
				return blMgr.Update()
			},
		}); err != nil {
			log.Printf("Warning: Failed to add blocklist_update task: %v", err)
		}

		// threat_update: daily 04:30 — VPN/proxy/Tor exit-node list refresh
		if err := sched.AddTask(&scheduler.Task{
			ID:       "threat_update",
			Name:     "Threat Intelligence Update",
			Schedule: scheduleFor("30 4 * * *", cfg.Server.Schedule.Tasks.ThreatUpdate),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.ThreatUpdate),
			Fn: func() error {
				log.Println("scheduler: running threat_update")
				return threatMgr.Update(threatLookup)
			},
		}); err != nil {
			log.Printf("Warning: Failed to add threat_update task: %v", err)
		}

		// cve_update: daily 05:00 (configurable)
		cveMgr := cve.NewCVEManager(filepath.Join(*dataDir, "security", "cve"), cfg.Data.CVE.Source)
		if err := sched.AddTask(&scheduler.Task{
			ID:       "cve_update",
			Name:     "CVE Database Update",
			Schedule: scheduleFor("0 5 * * *", cfg.Server.Schedule.Tasks.CVEUpdate),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.CVEUpdate),
			Fn: func() error {
				log.Println("scheduler: running cve_update")
				return cveMgr.Update()
			},
		}); err != nil {
			log.Printf("Warning: Failed to add cve_update task: %v", err)
		}

		// update_check: daily 06:00 — check for newer version (configurable)
		// Per AI.md PART 18 / PART 22: notify-only unless update.auto_install is true.
		if err := sched.AddTask(&scheduler.Task{
			ID:       "update_check",
			Name:     "Update Check",
			Schedule: scheduleFor("0 6 * * *", cfg.Server.Schedule.Tasks.UpdateCheck),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.UpdateCheck),
			Fn: func() error {
				log.Println("scheduler: running update_check")
				updateNotifiedPath := filepath.Join(dataDirPath, "update_notified_version")
				branch := cfg.Server.Update.Branch
				if branch == "" {
					branch = cfg.Server.UpdateBranch
				}
				if branch == "" {
					branch = "stable"
				}
				release, err := updater.CheckForUpdate(context.Background(), Version, branch, buildEpoch())
				if err != nil {
					return fmt.Errorf("update_check: %w", err)
				}
				if release == nil {
					log.Println("scheduler: update_check — already up to date")
					return nil
				}
				// Per AI.md PART 22: defer_days gates the scheduled task only.
				// A release must have been public for at least defer_days before the task
				// acts on it. Manual --update check / --update yes always ignores this window.
				if !updater.IsEligible(*release, cfg.Server.Update.DeferDays) {
					log.Printf("scheduler: update_check — release %s not yet eligible (defer_days=%d)", release.TagName, cfg.Server.Update.DeferDays)
					return nil
				}
				latestVersion := strings.TrimPrefix(release.TagName, "v")
				// AI.md PART 17 lists "Update available" at WARN, not INFO.
				log.Printf("WARN scheduler: update_check — update available: %s -> %s", Version, latestVersion)
				// update_available is a state-change event, not a per-run report.
				// The last notified version is persisted so a pending update
				// does not re-notify on every daily run until it is installed.
				alreadyNotified := readUpdateNotifiedVersion(updateNotifiedPath) == latestVersion
				// Per AI.md PART 22 (29592/29597): auto_install:false fires the
				// update_available event; the email is off by default and gated
				// by server.notifications.email.events.update_available.
				if !alreadyNotified && emailMgr != nil && emailMgr.IsEnabled() && cfg.Server.Notifications.Email.Events.UpdateAvailable {
					sendOperatorEmail(cfg, emailMgr, "update_available", map[string]string{
						"app_name":        projectName,
						"app_url":         cfg.Server.BaseURL,
						"current_version": Version,
						"new_version":     latestVersion,
						"channel":         branch,
					})
					writeUpdateNotifiedVersion(updateNotifiedPath, latestVersion)
				}
				if cfg.Server.Update.AutoInstall {
					log.Printf("scheduler: update_check — auto_install enabled, updating to %s", latestVersion)
					previousVersion := Version
					if err := updater.DoUpdate(context.Background(), release); err != nil {
						return fmt.Errorf("update_check auto-install: %w", err)
					}
					log.Printf("scheduler: update_check — updated to %s", latestVersion)
					// Per AI.md PART 22: update_installed fires on self-update completion.
					if emailMgr != nil && emailMgr.IsEnabled() && cfg.Server.Notifications.Email.Events.UpdateInstalled {
						sendOperatorEmail(cfg, emailMgr, "update_installed", map[string]string{
							"app_name":         projectName,
							"app_url":          cfg.Server.BaseURL,
							"previous_version": previousVersion,
							"new_version":      latestVersion,
							"timestamp":        time.Now().UTC().Format(time.RFC3339),
						})
					}
					if err := updater.RestartSelf(); err != nil {
						log.Printf("scheduler: update_check — restart failed: %v; restart manually", err)
					}
				}
				return nil
			},
		}); err != nil {
			log.Printf("Warning: Failed to add update_check task: %v", err)
		}

		// log_rotation: daily 00:00 — hand off to the log manager, which owns the
		// open file descriptors. Rotating behind its back (renaming or removing
		// the files directly) leaves every writer pointed at an unlinked inode.
		if err := sched.AddTask(&scheduler.Task{
			ID:       "log_rotation",
			Name:     "Log Rotation",
			Schedule: scheduleFor("0 0 * * *", cfg.Server.Schedule.Tasks.LogRotation),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.LogRotation),
			Fn: func() error {
				log.Println("scheduler: running log_rotation")
				return logMgr.Rotate()
			},
		}); err != nil {
			log.Printf("Warning: Failed to add log_rotation task: %v", err)
		}

		// backup_daily: daily 02:00 (configurable)
		if err := sched.AddTask(&scheduler.Task{
			ID:       "backup_daily",
			Name:     "Daily Backup",
			Schedule: scheduleFor("0 2 * * *", cfg.Server.Schedule.Tasks.BackupDaily),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.BackupDaily),
			Fn: func() error {
				log.Println("scheduler: running backup_daily")

				// AI.md PART 21: scheduled backups skip (with an audit log
				// warning) when compliance mode blocks the encryption
				// password source rather than failing the scheduler run.
				if _, pwErr := resolveBackupEncryptionPassword(cfg, false); pwErr != nil {
					log.Printf("scheduler: backup_daily skipped: %v", pwErr)
					if logMgr != nil {
						logMgr.WriteAuditEvent("", "backup.skipped_compliance", "backup", "warn", "failure", "", map[string]any{
							"reason": pwErr.Error(),
						})
					}
					return nil
				}

				backupDir := resolvedBackupDir
				if err := os.MkdirAll(backupDir, 0o755); err != nil {
					return fmt.Errorf("backup_daily: create dir: %w", err)
				}

				// AI.md PART 21 Backup Creation Flow step 2: check free disk
				// space before creating the backup; skip (with audit log) if
				// usage exceeds threshold or there isn't room for the backup.
				if skip, reason := backupDiskSpaceExceeded(backupDir, cfg.Server.Maintenance.Cleanup.DiskThreshold, logMgr); skip {
					log.Printf("scheduler: backup_daily skipped: %s", reason)
					return nil
				}

				// Per AI.md PART 21: scheduled daily fulls use a date-only
				// timestamp (manual/CLI backups use date+time).
				ts := time.Now().Format("2006-01-02")
				backupFile := filepath.Join(backupDir, fmt.Sprintf("ipgaze_backup_%s.tar.gz", ts))
				if err := maintenanceBackup(cfg, configDir, *dataDir, dirs.DB, backupFile, false, false, false, logMgr); err != nil {
					if notifyBackupFailed(cfg, emailMgr, projectName, err) {
						markCriticalTaskEmail("backup_daily")
					}
					return fmt.Errorf("backup_daily: %w", err)
				}
				// Per AI.md PART 21: also create/replace the daily incremental.
				dailyFile := filepath.Join(backupDir, "ipgaze-daily.tar.gz")
				if err := maintenanceBackup(cfg, configDir, *dataDir, dirs.DB, dailyFile, false, false, false, logMgr); err != nil {
					log.Printf("scheduler: backup_daily incremental failed: %v", err)
				} else if logMgr != nil {
					// AI.md PART 21: backup.daily_updated records the refreshed
					// daily incremental and what it was taken relative to.
					logMgr.WriteAuditEvent("", "backup.daily_updated", "backup", "info", "success", "", map[string]any{
						"filename": filepath.Base(dailyFile),
						"since":    filepath.Base(backupFile),
					})
				}

				// Apply retention policy only after successful creation/verification.
				applyBackupRetention(backupDir, cfg.Server.Backup.Retention, logMgr)
				notifyBackupComplete(cfg, emailMgr, projectName, backupFile)
				return nil
			},
		}); err != nil {
			log.Printf("Warning: Failed to add backup_daily task: %v", err)
		}

		// backup_hourly: every hour — disabled by default (configurable)
		if err := sched.AddTask(&scheduler.Task{
			ID:       "backup_hourly",
			Name:     "Hourly Backup",
			Schedule: scheduleFor("@hourly", cfg.Server.Schedule.Tasks.BackupHourly),
			Enabled:  enabledFor(false, cfg.Server.Schedule.Tasks.BackupHourly),
			Fn: func() error {
				log.Println("scheduler: running backup_hourly")

				if _, pwErr := resolveBackupEncryptionPassword(cfg, false); pwErr != nil {
					log.Printf("scheduler: backup_hourly skipped: %v", pwErr)
					if logMgr != nil {
						logMgr.WriteAuditEvent("", "backup.skipped_compliance", "backup", "warn", "failure", "", map[string]any{
							"reason": pwErr.Error(),
						})
					}
					return nil
				}

				backupDir := resolvedBackupDir
				if err := os.MkdirAll(backupDir, 0o755); err != nil {
					return fmt.Errorf("backup_hourly: create dir: %w", err)
				}
				if skip, reason := backupDiskSpaceExceeded(backupDir, cfg.Server.Maintenance.Cleanup.DiskThreshold, logMgr); skip {
					log.Printf("scheduler: backup_hourly skipped: %s", reason)
					return nil
				}
				backupFile := filepath.Join(backupDir, "ipgaze-hourly.tar.gz")
				if err := maintenanceBackup(cfg, configDir, *dataDir, dirs.DB, backupFile, false, false, false, logMgr); err != nil {
					if notifyBackupFailed(cfg, emailMgr, projectName, err) {
						markCriticalTaskEmail("backup_hourly")
					}
					return fmt.Errorf("backup_hourly: %w", err)
				}
				notifyBackupComplete(cfg, emailMgr, projectName, backupFile)
				return nil
			},
		}); err != nil {
			log.Printf("Warning: Failed to add backup_hourly task: %v", err)
		}

		sched.Start()
	}

	// Log the footer custom_html sanitization preview at startup per AI.md
	// PART 16 "Footer Customization" — raw input, sanitized output, and a
	// warning if the sanitizer modified the operator-supplied markup.
	config.LogFooterSanitizationPreview(cfg.Web.Footer.CustomHTML)

	// tor_health per AI.md PART 31.1: probe the live control connection every
	// 30 seconds and restart Tor when the probe fails. Registered here rather
	// than at spawn time because the scheduler is created after the drop.
	if torAvailable && sched != nil {
		if err := sched.AddTask(&scheduler.Task{
			ID:       "tor_health",
			Name:     "Tor Health Check",
			Schedule: scheduleFor("@every 30s", cfg.Server.Schedule.Tasks.TorHealth),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.TorHealth),
			Fn: func() error {
				if healthErr := torMgr.HealthCheck(); healthErr != nil {
					log.Printf("scheduler: tor_health — control probe failed (%v), restarting Tor", healthErr)
					if err := torMgr.Restart(); err != nil {
						return fmt.Errorf("tor_health: restart failed: %w", err)
					}
				}
				return nil
			},
		}); err != nil {
			log.Printf("Warning: Failed to add tor_health task: %v", err)
		}
	}

	// Initialize I2P eepsite per AI.md PART 31.2.
	// OPT-IN: unlike Tor, no provider is contacted and no port is allocated
	// unless server.i2p.enabled is explicitly true.
	i2pLogDir := dirs.Logs
	if envLog := os.Getenv("LOG_DIR"); envLog != "" {
		i2pLogDir = envLog
	}
	i2pMgr := i2p.NewI2PManager(i2p.I2PServiceConfig{
		ConfigDir:        configDir,
		DataDir:          *dataDir,
		LogDir:           i2pLogDir,
		Enabled:          cfg.Server.I2P.Enabled,
		Binary:           cfg.Server.I2P.Binary,
		SAMAddress:       cfg.Server.I2P.SAMAddress,
		VirtualPort:      cfg.Server.I2P.VirtualPort,
		InboundLength:    cfg.Server.I2P.InboundLength,
		OutboundLength:   cfg.Server.I2P.OutboundLength,
		InboundQuantity:  cfg.Server.I2P.InboundQuantity,
		OutboundQuantity: cfg.Server.I2P.OutboundQuantity,
		SignatureType:    cfg.Server.I2P.SignatureType,
		BootstrapTimeout: cfg.Server.I2P.BootstrapTimeout,
	})
	if cfg.Server.I2P.Enabled {
		if i2pMgr.IsAvailable() {
			if err := i2pMgr.Start(); err != nil {
				log.Printf("Warning: Failed to start I2P eepsite: %v", err)
			} else {
				log.Println("I2P eepsite starting (server binary controls I2P per PART 31.2)")
			}

			// i2p_health: every 10 minutes — only when I2P is enabled and a provider was found.
			if sched != nil {
				if err := sched.AddTask(&scheduler.Task{
					ID:       "i2p_health",
					Name:     "I2P Health Check",
					Schedule: "@every 10m",
					Enabled:  true,
					Fn: func() error {
						if !i2pMgr.IsRunning() {
							log.Println("scheduler: i2p_health — I2P not running, attempting restart")
							if err := i2pMgr.Start(); err != nil {
								return fmt.Errorf("i2p_health: restart failed: %w", err)
							}
						}
						return nil
					},
				}); err != nil {
					log.Printf("Warning: Failed to add i2p_health task: %v", err)
				}
			}
		} else {
			log.Println("I2P enabled but no provider found (i2pd binary or SAM bridge), eepsite disabled")
		}
	}

	// Setup signal handling
	// Per AI.md PART 27: Handle SIGRTMIN+3 (signal 37) for Docker STOPSIGNAL
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.Signal(37))
	// SIGHUP is ignored per AI.md PART 27 — config auto-reloads via the
	// ConfigManager file watcher below, not via a one-shot signal reload.
	signal.Ignore(syscall.SIGHUP)

	// Watch server.yml for external edits and hot-reload or flag
	// restart-required settings per AI.md PART 12.
	configMgr := config.NewConfigManager(configPath)
	stopConfigWatch := configMgr.Start()

	r := geoMgr.Reader()
	// Initialise the cache backend from config (type: none|memory|valkey|redis|memcache).
	// CACHE_URL (Runtime env var, e.g. from docker-compose.yml's valkey sidecar)
	// overrides server.yml's cache.url per AI.md PART 12.
	cache.ApplyEnvOverrides(&cfg.Server.Cache)
	appCache, cacheErr := cache.New(cfg.Server.Cache)
	if cacheErr != nil {
		log.Printf("warn: cache init failed (%v); falling back to memory cache", cacheErr)
		appCache, _ = cache.New(config.CacheConfig{Type: "memory"})
	}
	// Cache operation logging per AI.md PART 6 server.debug.log_cache —
	// gated by the debug flag, never by mode alone.
	if cfg.IsDebug() && cfg.Server.Debug.LogCache {
		appCache = cache.NewLogging(appCache)
	}
	defer appCache.Close()
	// Legacy in-server response cache for GeoIP result caching; separate from appCache.
	httpCache := server.NewCache(0)
	// Profiling endpoints enabled only in debug mode, not via a separate flag
	srv := server.NewHTTPServer(r, httpCache)
	// Default to the standard reverse-proxy header priority list per AI.md
	// PART 12 "Client IP Detection" when the operator has not overridden it
	// via --header; these are only honored for trusted peers (see
	// TrustResolver.IsTrustedPeer), so this is safe to enable unconditionally.
	if len(headers) == 0 {
		headers = defaultTrustedIPHeaders
	}
	srv.IPHeaders = headers
	srv.SetConfig(cfg)
	srv.SetEmailManager(emailMgr)
	// Cache SHA-256 of operator token in memory per AI.md PART 11.
	// Hash is never written to DB; raw token is stored only in server.yml (auto-generated above).
	srv.SetOperatorToken(cfg.Server.Token)
	srv.DataDir = *dataDir
	srv.ConfigDir = configDir
	srv.Version = Version
	srv.CommitID = CommitID
	srv.BuildDate = BuildDate
	srv.SetTorStatus(torMgr)
	// Live Tor manager behind the INTERNAL /server/tor/* control channel that
	// `ipgaze tor ...` drives over loopback (AI.md PART 31.1).
	srv.SetTorControl(torMgr)
	srv.SetI2PStatus(i2pMgr)
	srv.Mode = cfg.Server.Mode
	srv.BaseURL = *baseurlFlag
	// Per AI.md PART 13: /healthz root alias is optional, gated by config.
	srv.HealthzRootEnabled = cfg.Server.Healthz.Root.Enabled
	// HOST_IPV4 / HOST_IPV6: host's public IPs for container deployments.
	// Invalid values are silently ignored per spec.
	srv.SetHostIPs(os.Getenv("HOST_IPV4"), os.Getenv("HOST_IPV6"))

	// Initialize metrics per AI.md PART 20
	// ctx is declared below for graceful shutdown; use a local stop channel here.
	metricsStop := make(chan struct{})
	if cfg.Server.Metrics.Enabled {
		if cfg.Server.Metrics.IncludeRuntime {
			smetrics.RegisterRuntimeMetrics()
		}
		smetrics.InitAppInfo(Version, CommitID, BuildDate)
		srv.SetMetricsConfig(cfg.Server.Metrics)
		if cfg.Server.Metrics.IncludeRuntime {
			rc := smetrics.NewRuntimeCollector()
			rc.Start()
			defer rc.Stop()
		}
		smetrics.StartUptimeUpdater(metricsStop)
	}

	// Register scheduler tasks.
	// Per AI.md PART 18: healthcheck_self runs on every node.
	if sched != nil {
		// healthcheck_self: every 5 minutes (configurable)
		if err := sched.AddTask(&scheduler.Task{
			ID:       "healthcheck_self",
			Name:     "Self Health Check",
			Schedule: scheduleFor("@every 5m", cfg.Server.Schedule.Tasks.HealthcheckSelf),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.HealthcheckSelf),
			Fn: func() error {
				// Use the canonical /server/healthz path, not the /healthz root
				// alias — that alias is optional and disabled by default (AI.md
				// PART 13, srv.HealthzRootEnabled above), so this self-check
				// would always 404 on a default-config server.
				url := fmt.Sprintf("http://localhost:%s/server/healthz", serverPort)
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Get(url)
				if err != nil {
					log.Printf("scheduler: healthcheck_self failed: %v", err)
					return err
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					log.Printf("scheduler: healthcheck_self non-200: %d", resp.StatusCode)
					return fmt.Errorf("healthcheck_self: HTTP %d", resp.StatusCode)
				}
				return nil
			},
		}); err != nil {
			log.Printf("Warning: Failed to add healthcheck_self task: %v", err)
		}

		// token_cleanup: every 15 minutes — remove expired API tokens and sessions.
		// ipgaze is anonymous-only; no user tokens exist, so this is a required no-op per AI.md PART 18.
		if err := sched.AddTask(&scheduler.Task{
			ID:       "token_cleanup",
			Name:     "Token Cleanup",
			Schedule: scheduleFor("@every 15m", cfg.Server.Schedule.Tasks.TokenCleanup),
			Enabled:  enabledFor(true, cfg.Server.Schedule.Tasks.TokenCleanup),
			Fn: func() error {
				return nil
			},
		}); err != nil {
			log.Printf("Warning: Failed to add token_cleanup task: %v", err)
		}

		// public_ip_refresh: every 12h — fetch this server's own external public IP.
		// Per AI.md PART 18: registered after srv is created so the closure can call srv.RefreshPublicIP().
		if err := sched.AddTask(&scheduler.Task{
			ID:       "public_ip_refresh",
			Name:     "Public IP Refresh",
			Schedule: "@every 12h",
			Enabled:  true,
			Fn: func() error {
				if err := srv.RefreshPublicIP(); err != nil {
					log.Printf("scheduler: public_ip_refresh failed: %v", err)
					return err
				}
				log.Printf("scheduler: public_ip_refresh: server public IP is %s", srv.PublicIP())
				return nil
			},
		}); err != nil {
			log.Printf("Warning: Failed to add public_ip_refresh task: %v", err)
		}
		// Run once immediately at startup so the cached IP is available on first request.
		if err := srv.RefreshPublicIP(); err != nil {
			log.Printf("Warning: public_ip_refresh at startup failed: %v", err)
		}
	}

	// Build the trusted-proxy resolver per AI.md PART 12.
	// Strip bracket notation from IPv6 wildcard — NewTrustResolver expects a bare IP or empty string.
	bareListenIP := serverAddress
	if bareListenIP == "[::]" {
		bareListenIP = "::"
	}
	trust := netutil.NewTrustResolver(cfg.Server.TrustedProxies, bareListenIP)
	// Wire Tor onion address for priority-0 Tor request detection (AI.md PART 12).
	// Prefer the address the running hidden service actually generated over the
	// static server.yml value — the .onion address is auto-generated on first
	// run (AI.md PART 31 "App handles EVERYTHING"), so requiring an operator to
	// manually copy it into tor.onion_address would leave Tor request detection
	// (FQDN resolution, clearnet URL/email suppression, CORS, security.txt)
	// permanently inert on every fresh deployment.
	trust.OnionAddress = cfg.Tor.OnionAddress
	if hostname := torMgr.GetHostname(); hostname != "" {
		trust.OnionAddress = hostname
	}
	// Wire I2P eepsite address for priority-0 I2P request detection (AI.md
	// PART 31.2). No static server.yml equivalent exists — the .b32.i2p
	// address derives entirely from the persisted destination key.
	if hostname := i2pMgr.GetHostname(); hostname != "" {
		trust.I2PAddress = hostname
	}
	// trustCtx governs the DNS-refresh goroutine; cancelled during graceful shutdown.
	trustCtx, trustCancel := context.WithCancel(context.Background())
	trust.Start(trustCtx)
	srv.SetTrust(trust)

	// Configure middleware chain components per AI.md spec PART 5 / PART 9.
	// Rate limiter: per-class buckets from server.yml (AI.md PART 12 "Rate
	// Limiting"). Each bucket independently falls back to its
	// DefaultRateLimitConfig value when the configured requests/window is zero
	// or rate limiting is disabled entirely.
	rlCfg := server.DefaultRateLimitConfig()
	if cfg.Server.RateLimit.Enabled {
		rlCfg.Read = resolveRateBucket(cfg.Server.RateLimit.Read, rlCfg.Read)
		rlCfg.Write = resolveRateBucket(cfg.Server.RateLimit.Write, rlCfg.Write)
		rlCfg.Health = resolveRateBucket(cfg.Server.RateLimit.Health, rlCfg.Health)
		if cfg.Server.RateLimit.GlobalBurst > 0 {
			rlCfg.Global = server.RateLimitBucket{
				Limit:  cfg.Server.RateLimit.GlobalBurst,
				Window: time.Minute,
			}
		}
	}
	limiter := server.NewRateLimiter(rlCfg, trust)
	// AI.md PART 11: 429 rejections are security events and belong in security.log.
	if logMgr != nil {
		limiter.SetLogManager(logMgr)
	}
	// AI.md PART 17: security_alert on rate-limit blocks. Debounce per-IP so a
	// sustained flood doesn't send one email per rejected request.
	var securityAlertMu sync.Mutex
	securityAlertLast := make(map[string]time.Time)
	limiter.OnBlocked = func(clientIP string) {
		if emailMgr == nil || !emailMgr.IsEnabled() || !cfg.Server.Notifications.Email.Events.SecurityAlert {
			return
		}
		securityAlertMu.Lock()
		last, seen := securityAlertLast[clientIP]
		now := time.Now()
		if seen && now.Sub(last) < 15*time.Minute {
			securityAlertMu.Unlock()
			return
		}
		securityAlertLast[clientIP] = now
		securityAlertMu.Unlock()
		sendOperatorEmail(cfg, emailMgr, "security_alert", map[string]string{
			"app_name": projectName,
			"app_url":  cfg.Server.BaseURL,
			"message":  "Rate limit exceeded for " + clientIP,
			"ip":       clientIP,
			"time":     now.Format(time.RFC3339),
		})
	}
	srv.SetRateLimiter(limiter)

	// Allowlist: trusted IPs that bypass blocklist/rate-limit/geoip (not auth)
	if len(cfg.Server.Security.Allowlist) > 0 {
		entries := make([]server.AllowlistEntry, 0, len(cfg.Server.Security.Allowlist))
		for _, e := range cfg.Server.Security.Allowlist {
			entries = append(entries, server.AllowlistEntry{
				CIDR:        e.CIDR,
				Description: e.Description,
			})
		}
		srv.SetAllowlist(server.NewAllowlistLookup(entries))
	}

	// Blocklist: load downloaded firehol/spamhaus IP lists from disk
	blDir := filepath.Join(*dataDir, "security", "blocklists")
	blLookup := &blocklist.Lookup{}
	if err := blLookup.LoadDir(blDir); err != nil {
		log.Printf("Warning: failed to load blocklists from %s: %v", blDir, err)
	} else {
		srv.SetBlocklistLookup(blLookup)
	}

	// Threat intelligence: VPN, proxy, Tor exit-node detection in responses.
	srv.SetThreatLookup(threatLookup)

	// GeoIP country blocking (deny / allow lists from config)
	// Preset names (AI.md PART 19) must be expanded to country codes before the
	// server compares them against a resolved ISO code.
	srv.SetGeoIPCountries(cfg.Server.GeoIP.ResolvedDenyCountries(), cfg.Server.GeoIP.ResolvedAllowCountries())

	// Wire scheduler and DB to server for /debug/scheduler and /debug/db endpoints.
	if sched != nil {
		srv.SetScheduler(sched)
	}
	if serverDB != nil {
		srv.SetDB(serverDB)
	}

	// Wire the app cache backend and disk-space helper for /server/healthz
	// checks.cache and checks.disk probes (AI.md PART 13).
	if appCache != nil {
		srv.SetCacheBackend(appCache)
	}
	srv.SetDiskUsageFunc(diskFreeAndUsedPercent)

	// Wire the log manager (opened earlier, before scheduler task registration)
	// into the HTTP server and emit the startup audit event.
	if logMgr != nil {
		srv.SetLogManager(logMgr)
		logMgr.WriteAuditEvent("", "server.started", "server", "info", "success", "", map[string]any{
			"version": Version,
			"commit":  CommitID,
			"port":    serverPort,
		})
		logMgr.WriteServer("info", fmt.Sprintf("%s %s (%s) starting on port %s", projectName, Version, CommitID, serverPort))
	}

	// AI.md PART 21: server log warning on startup when backup encryption is
	// not configured (dismissable after encryption is configured — since this
	// project has no admin web UI, "dismissable" means the warning stops once
	// server.yml sets backup.encryption.enabled: true).
	if !cfg.Server.Backup.Encryption.Enabled {
		log.Printf("Warning: backup encryption is not configured — backups will be stored unencrypted. Set server.backup.encryption.enabled: true in server.yml to secure backups.")
		if logMgr != nil {
			logMgr.WriteApp("warn", "backup encryption is not configured", "component", "backup")
			logMgr.WriteAuditEvent("", "backup.encryption_not_configured", "backup", "warn", "success", "", map[string]any{
				"message": "backup encryption is not configured; backups are stored unencrypted",
			})
		}
	}

	// Reverse hostname lookup and port reachability testing are always available —
	// AI.md "No feature gating: ALL features available to ALL users, ALWAYS" (line
	// 331) and the zero-config first-run rule both rule out an opt-in flag here.
	srv.LookupAddr = iputil.LookupAddr
	srv.LookupPort = iputil.LookupPort
	if len(headers) > 0 {
		log.Printf("Trusting remote IP from header(s): %s", headers.String())
	}

	// Set up Swagger/OpenAPI handler
	srv.SwaggerHandler = swagger.Handler(swagger.SwaggerHandlerConfig{
		Version:  Version,
		CommitID: CommitID,
		Trust:    trust,
	})
	// /api/swagger and /api/{api_version}/server/swagger are dedicated JSON
	// spec endpoints (AI.md PART 14/16) — always application/json, never the
	// interactive UI that the content-negotiating SwaggerHandler falls back to.
	srv.SwaggerJSONHandler = swagger.JSONHandler(swagger.SwaggerHandlerConfig{
		Version:  Version,
		CommitID: CommitID,
		Trust:    trust,
	})

	// Set up GraphQL handler — shares IP/port lookup logic with the REST
	// handlers by wiring the same Server methods used there.
	srv.GraphQLHandler = gql.Handler(gql.GraphQLHandlerConfig{
		Version:   Version,
		CommitID:  CommitID,
		ClientIP:  srv.RequestIP,
		LookupIP:  srv.LookupIP,
		CheckPort: srv.CheckPort,
		// Resolved lazily: HealthHandler is constructed during route setup, so a
		// method value taken here would bind a nil receiver permanently.
		Health: func() model.HealthResponse { return srv.HealthHandler.HealthSnapshot() },
	})

	// Print startup banner. Per AI.md PART 12 startup step 20 the banner's
	// "Listening on" line ALWAYS shows the resolved {proto}://{fqdn}[:{port}]
	// and never the raw bind address — a wildcard bind such as 0.0.0.0, ::,
	// or [::] is explicitly WRONG in the URL Display Rules. Raw bind addresses
	// remain acceptable in the log line emitted further below.
	bannerProto := "http"
	bannerPort := httpPort
	if httpsListener != nil {
		bannerProto = "https"
		bannerPort = "443"
		if httpsPort != "" {
			bannerPort = httpsPort
		}
	}
	// With no configured FQDN the banner falls back to a globally reachable
	// address rather than a development TLD (AI.md URL Display Rules).
	bannerURL := bannerProto + "://" + bannerDisplayHost(cfg.Server.FQDN, serverAddress) + bannerPortSuffix(bannerProto, bannerPort)
	if strings.TrimSpace(cfg.Server.FQDN) == "" {
		bannerURL = netutil.GetDisplayURL(projectName, bannerPort, bannerProto == "https")
	}
	bannerURLs := []string{bannerURL}
	banner.PrintStartupBanner(banner.BannerPrintConfig{
		AppName:   binaryName,
		Version:   Version,
		AppMode:   cfg.Server.Mode,
		Debug:     *debugMode,
		URLs:      bannerURLs,
		StartedAt: time.Now(),
	})

	// Parse configurable HTTP timeouts from server.yml; fall back to spec defaults.
	readTimeout := parseDurationOrDefault(cfg.Server.Limits.ReadTimeout, 30*time.Second)
	writeTimeout := parseDurationOrDefault(cfg.Server.Limits.WriteTimeout, 30*time.Second)
	idleTimeout := parseDurationOrDefault(cfg.Server.Limits.IdleTimeout, 120*time.Second)

	// Wire the app handler into the Tor hidden-service backend listener now
	// that srv is fully configured. Per AI.md PART 31.1 the onion address
	// is served from a dedicated loopback backend port, never the clearnet
	// HTTP/HTTPS port. Safe to call even if Tor never started or is not
	// available (ServeBackend is a no-op until Start() has run).
	torMgr.ServeBackend(srv.Handler())

	// Wire the app handler into the I2P eepsite backend listener, mirroring
	// the Tor wiring above (AI.md PART 31.2). Safe to call even if I2P is
	// disabled or never started (ServeBackend is a no-op until Start() has run).
	i2pMgr.ServeBackend(srv.Handler())

	// errChan collects fatal errors from background server goroutines.
	errChan := make(chan error, 2)

	// Start HTTPS + HTTP-redirect when SSL is enabled, otherwise plain HTTP.
	// Per AI.md PART 15: Let's Encrypt autocert, TLS 1.2 min, self-signed fallback for dev.
	var httpServer *http.Server
	var httpsServer *http.Server

	// Both listeners were bound before privileges were dropped (AI.md PART 23),
	// so the servers here only ever call Serve on an already-open socket.
	if httpsListener != nil {
		// Resolve TLS config: try existing certs first, then Let's Encrypt, then self-signed for dev.
		tlsCfg, tlsErr := sslMgr.GetTLSConfig(sslDomains)
		if tlsErr != nil {
			if cfg.Server.Mode == "development" || cfg.Server.Mode == "debug" {
				log.Printf("SSL: no cert available (%v), using self-signed for development", tlsErr)
				tlsCfg, tlsErr = ssl.GenerateSelfSignedTLSConfig(sslDomains)
			}
			if tlsErr != nil {
				log.Printf("SSL: failed to obtain TLS config: %v", tlsErr)
				httpListener.Close()  //nolint:errcheck
				httpsListener.Close() //nolint:errcheck
				os.Exit(exConfig)
			}
		}

		httpsServer = &http.Server{
			Handler:      srv.Handler(),
			TLSConfig:    tlsCfg,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		}

		// In dual-port mode ("8090,8443") the HTTP half serves the application
		// directly; in single-port SSL mode it redirects to HTTPS and answers
		// ACME HTTP-01 challenges via autocert.Manager (AI.md PART 12, PART 15).
		httpHandler := srv.Handler()
		if httpsPort == "" {
			httpHandler = sslMgr.GetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}))
		}
		httpServer = &http.Server{
			Handler:      httpHandler,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		}

		go func() {
			if err := httpServer.Serve(httpListener); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTP server error: %v", err)
			}
		}()
		go func() {
			if err := httpsServer.ServeTLS(httpsListener, "", ""); err != nil && err != http.ErrServerClosed {
				errChan <- err
			}
		}()
		log.Printf("Listening on HTTPS %s (HTTP %s)", httpsListenAddr, httpListenAddr)
		if logMgr != nil {
			logMgr.WriteServer("info", fmt.Sprintf("listening on HTTPS %s (HTTP %s)", httpsListenAddr, httpListenAddr))
		}
	} else {
		// Plain HTTP server on the listener bound while still privileged.
		httpServer = &http.Server{
			Handler:      srv.Handler(),
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		}
		go func() {
			if err := httpServer.Serve(httpListener); err != nil && err != http.ErrServerClosed {
				errChan <- err
			}
		}()
		if logMgr != nil {
			logMgr.WriteServer("info", fmt.Sprintf("listening on HTTP %s", httpListenAddr))
		}
	}

	// Wait for shutdown signal or server error
	for {
		select {
		case err := <-errChan:
			stopConfigWatch()
			torMgr.Stop()
			i2pMgr.Stop()
			sched.Stop()
			removePIDFile(pidFile)
			log.Printf("server error: %v", err)
			if logMgr != nil {
				logMgr.WriteServer("error", fmt.Sprintf("server error: %v", err))
			}
			os.Exit(exSoftware)
		case sig := <-sigChan:
			// Graceful shutdown per AI.md spec — 30-second drain timeout.
			// SIGHUP never reaches here (ignored above); every other notified
			// signal (SIGTERM, SIGINT, SIGRTMIN+3) shuts down gracefully.
			log.Printf("Received signal %v, shutting down gracefully...", sig)
			if logMgr != nil {
				logMgr.WriteServer("info", fmt.Sprintf("received signal %v, shutting down gracefully", sig))
			}
			// Flip health to shutting_down before the drain starts so load
			// balancers stop sending new work during the 30s window (AI.md PART 13).
			if srv.HealthHandler != nil {
				srv.HealthHandler.MarkShuttingDown()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

			// Shutdown HTTPS server if running
			if httpsServer != nil {
				if err := httpsServer.Shutdown(ctx); err != nil {
					log.Printf("HTTPS server shutdown error: %v", err)
				}
			}

			// Shutdown HTTP server (either plain or redirect)
			if httpServer != nil {
				if err := httpServer.Shutdown(ctx); err != nil {
					log.Printf("HTTP server shutdown error: %v", err)
				}
			}
			cancel()

			// Stop child processes
			stopConfigWatch()
			trustCancel()
			torMgr.Stop()
			i2pMgr.Stop()
			sched.Stop()
			close(metricsStop)

			// Remove PID file on clean shutdown per AI.md PART 7.
			removePIDFile(pidFile)

			log.Println("Graceful shutdown complete")
			if logMgr != nil {
				logMgr.WriteServer("info", "graceful shutdown complete")
			}
			os.Exit(0)
		}
	}
}

// parseDurationOrDefault parses a duration string (e.g. "30s", "2m") and
// returns the fallback value when the string is empty or unparseable.
func parseDurationOrDefault(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		log.Printf("Warning: invalid timeout %q, using default %s", s, fallback)
		return fallback
	}
	return d
}

// isWildcardBindAddress reports whether host is an "any address" bind value
// that must never be shown to a user (AI.md PART 8 URL Display Rules).
func isWildcardBindAddress(host string) bool {
	switch strings.TrimSpace(host) {
	case "", "0.0.0.0", "::", "[::]", "[::0]", "0:0:0:0:0:0:0:0":
		return true
	}
	return false
}

// bannerDisplayHost resolves the host shown in the startup banner: the
// configured FQDN when set, else the bind address when it is a real address,
// else the FQDN resolved from the environment (DOMAIN, hostname, public IP,
// localhost). IPv6 literals are returned bracketed so they concatenate into a
// valid URL with a port suffix.
func bannerDisplayHost(configuredFQDN, bindAddress string) string {
	host := strings.TrimSpace(configuredFQDN)
	if isWildcardBindAddress(host) {
		host = strings.TrimSpace(bindAddress)
	}
	if isWildcardBindAddress(host) {
		host = netutil.GetFQDN()
	}
	if strings.HasPrefix(host, "[") {
		return host
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

// bannerPortSuffix returns ":{port}" unless port is the default for proto,
// in which case the banner shows the URL without an explicit port.
func bannerPortSuffix(proto, port string) string {
	switch {
	case port == "":
		return ""
	case proto == "http" && port == "80":
		return ""
	case proto == "https" && port == "443":
		return ""
	}
	return ":" + port
}

func printHelp(binaryName string) {
	fmt.Printf(`%s %s - IP address lookup service with GeoIP information

Usage:
  %s [flags]

Information:
  -h, --help                        Show help (--help for any command shows its help)
  -v, --version                     Show version
      --status                      Show server status and health

Shell Integration:
      --shell completions [SHELL]   Print shell completions
      --shell init [SHELL]          Print shell init command
      --shell --help                Show shell help

Server Configuration:
      --mode {production|development}  Application mode (default: production)
      --config DIR                  Config directory
      --data DIR                    Data directory
      --cache DIR                   Cache directory
      --log DIR                     Log directory
      --backup DIR                  Backup directory
      --include-ssl                 Include SSL/TLS keys in backup (default: excluded)
      --include-data                Include full data dir in backup (default: excluded)
      --pid FILE                    PID file path
      --address ADDR                Listen address (default: 0.0.0.0)
      --port PORT                   Listen port (default: random 64xxx, 80 in container)
      --baseurl PATH                URL path prefix (default: /)
      --daemon                      Run as daemon (detach from terminal)
      --debug                       Enable debug mode
      --color {auto|yes|no}         Color output (default: auto)
      --lang CODE                   Language for output (default: auto)

Additional Options:
      --header HEADER               Header to trust for remote IP (repeatable)

Service Management:
      --service CMD                 Service management (--service --help for details)
      --maintenance CMD             Maintenance operations (--maintenance --help for details)
      --update [CMD]                Check/perform updates (--update --help for details)

Run '%s <command> --help' for detailed help on any command.
`, binaryName, Version, binaryName, binaryName)
}

// applyModeString parses a mode string (from the MODE env var or the --mode
// flag) via appmode.ParseModeWithDebugAlias and applies it to cfg.Server.Mode
// per AI.md PART 6. When the string is the "debug" alias, DEBUG is forced on
// unless it was already explicitly set — an explicit DEBUG env var or
// --debug flag always wins over the alias. Returns the parse error (if any)
// unchanged so callers can report it in their own format.
func applyModeString(cfg *config.AppConfig, modeStr string) error {
	resolvedMode, impliedDebug, err := appmode.ParseModeWithDebugAlias(modeStr)
	if err != nil {
		return err
	}
	cfg.Server.Mode = string(resolvedMode)
	if impliedDebug {
		if _, set := os.LookupEnv("DEBUG"); !set {
			os.Setenv("DEBUG", "true")
		}
	}
	return nil
}

// getLanguage resolves the output language using the priority chain from AI.md PART 30:
// 1. --lang flag  2. config file  3. LC_ALL env  4. LANG env  5. default "en"
func getLanguage(flagLang string) string {
	if flagLang != "" {
		return validateLang(flagLang)
	}
	if lang := os.Getenv("LC_ALL"); lang != "" {
		return validateLang(strings.Split(lang, "_")[0])
	}
	if lang := os.Getenv("LANG"); lang != "" {
		return validateLang(strings.Split(lang, "_")[0])
	}
	return "en"
}

// validateLang returns lang if it is a supported locale, otherwise "en".
func validateLang(lang string) string {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if i18n.IsSupported(lang) {
		return lang
	}
	return "en"
}

// handleShellCommand handles --shell completions/init commands
func handleShellCommand(cmd, binaryName string) {
	args := flag.Args()
	shell := ""
	if len(args) > 0 {
		shell = args[0]
	}
	if shell == "" {
		// Auto-detect shell from SHELL env
		shell = filepath.Base(os.Getenv("SHELL"))
	}

	switch cmd {
	case "completions":
		printShellCompletions(binaryName, shell)
	case "init":
		printShellInit(binaryName, shell)
	case "--help":
		fmt.Printf(`Shell integration commands:

  %s --shell completions [SHELL]   Print shell completions
  %s --shell init [SHELL]          Print shell init for eval

Supported shells: bash, zsh, fish

Examples:
  # Add to ~/.bashrc
  eval "$(%s --shell init bash)"

  # Or source completions directly
  source <(%s --shell completions zsh)
`, binaryName, binaryName, binaryName, binaryName)
	default:
		fmt.Printf("Unknown shell command: %s\n", cmd)
		fmt.Println("Available: completions, init, --help")
		os.Exit(exUsage)
	}
}

func printShellCompletions(binaryName, shell string) {
	switch shell {
	case "bash":
		fmt.Printf(`# %s bash completions
_%s_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="--help --version --status --config --data --port --address --mode --service --maintenance --update --shell --debug --color --daemon"
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
}
complete -F _%s_completions %s
`, binaryName, binaryName, binaryName, binaryName)
	case "zsh":
		fmt.Printf(`#compdef %s
_arguments \
    '-h[Show help]' \
    '--help[Show help]' \
    '-v[Show version]' \
    '--version[Show version]' \
    '--status[Show server status]' \
    '--config[Config directory]:directory:_files -/' \
    '--data[Data directory]:directory:_files -/' \
    '--port[Server port]:port:' \
    '--address[Server address]:address:' \
    '--mode[Application mode]:(production development)' \
    '--debug[Enable debug mode]' \
    '--daemon[Run as daemon]' \
    '--color[Color output]:(auto yes no)' \
    '--service[Service command]:(start stop restart reload status --install --uninstall --disable --help)' \
    '--maintenance[Maintenance command]:(backup restore update mode setup)' \
    '--update[Update command]:(check yes branch --help)' \
    '--shell[Shell command]:(completions init --help)'
`, binaryName)
	case "fish":
		fmt.Printf(`# %s fish completions
complete -c %s -l help -d 'Show help'
complete -c %s -l version -d 'Show version'
complete -c %s -l status -d 'Show server status'
complete -c %s -l config -d 'Config directory' -ra '(__fish_complete_directories)'
complete -c %s -l data -d 'Data directory' -ra '(__fish_complete_directories)'
complete -c %s -l port -d 'Server port'
complete -c %s -l address -d 'Server address'
complete -c %s -l mode -d 'Application mode' -xa 'production development'
complete -c %s -l debug -d 'Enable debug mode'
complete -c %s -l daemon -d 'Run as daemon'
complete -c %s -l color -d 'Color output' -xa 'auto yes no'
`, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName)
	default:
		fmt.Printf("Unknown shell: %s\n", shell)
		fmt.Println("Supported: bash, zsh, fish")
		os.Exit(exUsage)
	}
}

func printShellInit(binaryName, shell string) {
	switch shell {
	case "bash":
		fmt.Printf(`source <(%s --shell completions bash)
`, binaryName)
	case "zsh":
		fmt.Printf(`eval "$(%s --shell completions zsh)"
`, binaryName)
	case "fish":
		fmt.Printf(`%s --shell completions fish | source
`, binaryName)
	default:
		fmt.Printf("Unknown shell: %s\n", shell)
		os.Exit(exUsage)
	}
}

func checkHealth(port string) error {
	// Probe the always-registered public health endpoint, not the optional
	// /healthz root alias (disabled by default per AI.md PART 13) which would
	// make --status permanently fail and put a container HEALTHCHECK into a
	// restart loop even while the server is healthy.
	url := fmt.Sprintf("http://127.0.0.1:%s/server/healthz", port)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	return nil
}

func handleServiceCommand(cmd, _ string) {
	// Service install/uninstall require elevated privileges per AI.md PART 23.
	// Attempt escalation if needed and the user can escalate.
	if (cmd == "--install" || cmd == "--uninstall") && !isElevated() {
		if canEscalate() {
			if err := execElevated(os.Args); err != nil {
				fmt.Fprintf(os.Stderr, "Escalation failed: %v\n", err)
				os.Exit(exNoPerm)
			}
			return
		}
		fmt.Fprintln(os.Stderr, "Error: Service management requires administrator privileges.")
		fmt.Fprintln(os.Stderr, "You do not have sudo access. Contact your system administrator.")
		os.Exit(exNoPerm)
	}

	s := svc.NewSystemServiceManager()
	var err error
	switch cmd {
	case "start":
		err = s.Start()
	case "stop":
		err = s.Stop()
	case "restart":
		err = s.Restart()
	case "reload":
		err = s.Reload()
	case "status":
		err = s.Status()
	case "--install":
		err = s.Install()
	case "--uninstall":
		// Confirmation prompt is handled inside Uninstall().
		err = s.Uninstall()
	case "--disable":
		err = s.Disable()
	case "--help":
		fmt.Println("Service commands: start, stop, restart, reload, status, --install, --uninstall, --disable")
	default:
		fmt.Printf("Unknown service command: %s\n", cmd)
		os.Exit(exUsage)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Service command %q failed: %v\n", cmd, err)
		os.Exit(exOsErr)
	}
}

// resolveRateBucket converts one server.yml rate-limit bucket into a runtime
// bucket, falling back to the supplied default when the configured values are
// missing or non-positive (AI.md PART 12 "Rate Limiting").
func resolveRateBucket(cfgBucket config.RateLimitBucketConfig, fallback server.RateLimitBucket) server.RateLimitBucket {
	bucket := fallback
	if cfgBucket.Requests > 0 {
		bucket.Limit = cfgBucket.Requests
	}
	if cfgBucket.Window > 0 {
		bucket.Window = time.Duration(cfgBucket.Window) * time.Second
	}
	return bucket
}

// buildLogConfig converts cfg.Server.Logging into an applog.Config, ready to
// pass to applog.NewManager. Shared by the normal server-start path and by
// maintenance subcommands (e.g. `--maintenance pgp`) that need their own
// audit-log manager before the main server's log manager exists.
func buildLogConfig(cfg *config.AppConfig) applog.Config {
	return applog.Config{
		Level: cfg.Server.Logging.Level,
		// Syslog and CEF lines carry the process identity (AI.md PART 11).
		Program: projectName,
		Version: Version,
		Access: applog.LogFileConfig{
			Enabled:  cfg.Server.Logging.Access.Enabled,
			Filename: cfg.Server.Logging.Access.Filename,
			Format:   cfg.Server.Logging.Access.Format,
			Rotate:   cfg.Server.Logging.Access.Rotate,
			Keep:     cfg.Server.Logging.Access.Keep,
		},
		Server: applog.LogFileConfig{
			Enabled:  cfg.Server.Logging.Server.Enabled,
			Filename: cfg.Server.Logging.Server.Filename,
			Format:   cfg.Server.Logging.Server.Format,
			Rotate:   cfg.Server.Logging.Server.Rotate,
			Keep:     cfg.Server.Logging.Server.Keep,
		},
		Error: applog.LogFileConfig{
			Enabled:  cfg.Server.Logging.Error.Enabled,
			Filename: cfg.Server.Logging.Error.Filename,
			Format:   cfg.Server.Logging.Error.Format,
			Rotate:   cfg.Server.Logging.Error.Rotate,
			Keep:     cfg.Server.Logging.Error.Keep,
		},
		App: applog.LogFileConfig{
			Enabled:  cfg.Server.Logging.App.Enabled,
			Filename: cfg.Server.Logging.App.Filename,
			Format:   cfg.Server.Logging.App.Format,
			Rotate:   cfg.Server.Logging.App.Rotate,
			Keep:     cfg.Server.Logging.App.Keep,
		},
		Auth: applog.LogFileConfig{
			Enabled:  cfg.Server.Logging.Auth.Enabled,
			Filename: cfg.Server.Logging.Auth.Filename,
			Format:   cfg.Server.Logging.Auth.Format,
			Rotate:   cfg.Server.Logging.Auth.Rotate,
			Keep:     cfg.Server.Logging.Auth.Keep,
		},
		Audit: applog.AuditLogConfig{
			LogFileConfig: applog.LogFileConfig{
				Enabled:  cfg.Server.Logging.Audit.Enabled,
				Filename: cfg.Server.Logging.Audit.Filename,
				Format:   cfg.Server.Logging.Audit.Format,
				Rotate:   cfg.Server.Logging.Audit.Rotate,
				Keep:     cfg.Server.Logging.Audit.Keep,
			},
			Compress:         cfg.Server.Logging.Audit.Compress,
			IncludeUserAgent: cfg.Server.Logging.Audit.IncludeUserAgent,
			Events: applog.AuditEventFilter{
				Configuration: cfg.Server.Logging.Audit.Events.Configuration,
				Security:      cfg.Server.Logging.Audit.Events.Security,
				Backup:        cfg.Server.Logging.Audit.Events.Backup,
				Server:        cfg.Server.Logging.Audit.Events.Server,
			},
		},
		Security: applog.LogFileConfig{
			Enabled:  cfg.Server.Logging.Security.Enabled,
			Filename: cfg.Server.Logging.Security.Filename,
			Format:   cfg.Server.Logging.Security.Format,
			Rotate:   cfg.Server.Logging.Security.Rotate,
			Keep:     cfg.Server.Logging.Security.Keep,
		},
		Debug: applog.LogFileConfig{
			Enabled:  cfg.Server.Logging.Debug.Enabled,
			Filename: cfg.Server.Logging.Debug.Filename,
			Format:   cfg.Server.Logging.Debug.Format,
			Rotate:   cfg.Server.Logging.Debug.Rotate,
			Keep:     cfg.Server.Logging.Debug.Keep,
		},
	}
}

// requireOperatorAuth implements the AI.md PART 5 "Sensitive Operations"
// authorization gate: root/elevated processes pass automatically; anyone
// else must supply the current server.token (constant-time compared).
func requireOperatorAuth(cfg *config.AppConfig, prompt string) bool {
	if isElevated() {
		return true
	}
	if cfg.Server.Token == "" {
		return false
	}
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	entered, _ := reader.ReadString('\n')
	entered = strings.TrimSpace(entered)
	return subtle.ConstantTimeCompare([]byte(entered), []byte(cfg.Server.Token)) == 1
}

// requireTypedConfirmation prompts the operator to type an exact phrase
// back, used to gate irreversible/high-impact maintenance actions (PGP
// export private, import, delete).
func requireTypedConfirmation(expected, prompt string) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	entered, _ := reader.ReadString('\n')
	return strings.TrimSpace(entered) == expected
}

// openMaintenanceDB opens server.db independently of the main server
// startup path, for maintenance subcommands (e.g. `--maintenance pgp`)
// that run and exit before the server's own DB connection is created.
// Mirrors the driver-selection/schema logic in main().
func openMaintenanceDB(cfg *config.AppConfig, dirs paths.Directories) (*sql.DB, error) {
	dbCfg := cfg.Server.Database
	if dbCfg.NormalizedDriver() == "libsql" {
		if valErr := dbCfg.ValidateLibSQL(); valErr != nil {
			dbCfg.Driver = "sqlite"
		}
	}

	// Delegates driver selection, connection pooling, PRAGMA setup, and schema
	// application to db.NewDB so this logic has a single implementation
	// (mirrors the server's own DB open in main()). dirs.DB (not dirs.Data)
	// is authoritative per PART 4/12: it honors the independently-relocatable
	// DATABASE_DIR env var.
	conn, err := db.NewDB(&dbCfg, dirs.DB)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", dbCfg.NormalizedDriver(), err)
	}
	return conn, nil
}

// pgpExportRateLimitWindow bounds `--maintenance pgp export private` to once
// per hour per AI.md PART 11 "Export private".
const pgpExportRateLimitWindow = time.Hour

// pgpExportMarkerPath returns the on-disk marker used to rate-limit private
// key exports (mtime/contents = unix timestamp of the last export).
func pgpExportMarkerPath(configDir string) string {
	return filepath.Join(configDir, "security", ".private_key_export_at")
}

// pgpExportRateLimitRemaining returns how much longer the operator must wait
// before another `pgp export private` is allowed, or 0 if allowed now.
func pgpExportRateLimitRemaining(configDir string) time.Duration {
	data, err := os.ReadFile(pgpExportMarkerPath(configDir))
	if err != nil {
		return 0
	}
	last, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	elapsed := time.Since(time.Unix(last, 0))
	if elapsed >= pgpExportRateLimitWindow {
		return 0
	}
	return pgpExportRateLimitWindow - elapsed
}

// pgpMarkExportTimestamp records "now" as the last private-key export time.
func pgpMarkExportTimestamp(configDir string) {
	dir := filepath.Join(configDir, "security")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(pgpExportMarkerPath(configDir), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600)
}

// handlePGPMaintenance dispatches `--maintenance pgp <action>` subcommands
// per AI.md PART 11 "GPG Keypair Management". Every action requires operator
// authorization (server.token OR root/elevated); export private, import, and
// delete additionally require typed confirmation and are audit-logged.
func handlePGPMaintenance(args []string, configDir, logsDir, configPath string, cfg *config.AppConfig) {
	if len(args) == 0 {
		fmt.Println("Usage: ipgaze --maintenance pgp <generate|rotate|publish|export|import|delete>")
		os.Exit(exUsage)
	}

	if !requireOperatorAuth(cfg, "This is a sensitive PGP key operation. Enter operator token to confirm: ") {
		fmt.Println("Authorization required: run as root/administrator, or provide a valid operator token.")
		os.Exit(exNoPerm)
	}

	dirs := paths.GetDirectories()
	conn, err := openMaintenanceDB(cfg, dirs)
	if err != nil {
		log.Printf("pgp: failed to open database: %v", err)
		os.Exit(exIoErr)
	}
	defer conn.Close()

	logMgr, logMgrErr := applog.NewManager(logsDir, buildLogConfig(cfg))
	if logMgrErr != nil {
		log.Printf("Warning: pgp: failed to open audit log: %v", logMgrErr)
		logMgr = nil
	} else {
		defer logMgr.Close()
	}

	appName := projectName
	securityContact := cfg.Web.Security.Contact
	if securityContact == "" {
		securityContact = "security@localhost"
	}

	action, rest := args[0], args[1:]
	switch action {
	case "generate":
		pgpGenerate(conn, configDir, appName, securityContact, cfg, logMgr)
	case "rotate":
		pgpRotate(conn, configDir, appName, securityContact, cfg, logMgr)
	case "publish":
		pgpPublishKeyservers(conn, configDir, cfg, logMgr)
	case "export":
		if len(rest) == 0 {
			fmt.Println("Usage: ipgaze --maintenance pgp export <public|private> [path]")
			os.Exit(exUsage)
		}
		switch rest[0] {
		case "public":
			path := ""
			if len(rest) > 1 {
				path = rest[1]
			}
			pgpExportPublic(configDir, path)
		case "private":
			if len(rest) < 2 {
				fmt.Println("Usage: ipgaze --maintenance pgp export private <path>")
				os.Exit(exUsage)
			}
			pgpExportPrivate(conn, configDir, rest[1], logMgr)
		default:
			fmt.Printf("Unknown export target: %s (expected public or private)\n", rest[0])
			os.Exit(exUsage)
		}
	case "import":
		if len(rest) == 0 {
			fmt.Println("Usage: ipgaze --maintenance pgp import <file>")
			os.Exit(exUsage)
		}
		pgpImport(conn, configDir, rest[0], appName, securityContact, logMgr)
	case "delete":
		pgpDelete(conn, configDir, cfg, logMgr)
	default:
		fmt.Printf("Unknown pgp command: %s\n", action)
		fmt.Println("Available: generate, rotate, publish, export, import, delete")
		os.Exit(exUsage)
	}
	_ = configPath
}

// pgpGenerate implements `--maintenance pgp generate` (AI.md PART 11 "Generate").
func pgpGenerate(conn *sql.DB, configDir, appName, securityContact string, cfg *config.AppConfig, logMgr *applog.Manager) {
	secret, err := security.GetOrCreateSecret(conn, security.SecretInstallationSecret)
	if err != nil {
		log.Printf("pgp generate: load installation secret: %v", err)
		os.Exit(exSoftware)
	}
	kp, err := pgp.Generate(appName, securityContact)
	if err != nil {
		log.Printf("pgp generate: %v", err)
		os.Exit(exSoftware)
	}
	if err := pgp.Save(configDir, kp, secret); err != nil {
		log.Printf("pgp generate: save: %v", err)
		os.Exit(exIoErr)
	}
	if err := pgp.InsertRecord(conn, kp.Fingerprint, kp.CreatedAt, kp.ExpiresAt); err != nil {
		log.Printf("pgp generate: record: %v", err)
		os.Exit(exSoftware)
	}
	if logMgr != nil {
		logMgr.WriteAuditEvent("", "security.pgp_key_generated", "security", "info", "success", "", map[string]any{
			"fingerprint": kp.Fingerprint,
			"expires_at":  kp.ExpiresAt.Format(time.RFC3339),
		})
	}
	fmt.Printf("Generated PGP keypair: %s\n", kp.Fingerprint)
	fmt.Printf("Expires: %s\n", kp.ExpiresAt.Format("2006-01-02"))

	if cfg.Web.Security.PublishPGPKey && len(cfg.Web.Security.Keyservers) > 0 {
		publishToKeyservers(conn, configDir, kp.Fingerprint, kp.PublicArmor, cfg.Web.Security.Keyservers)
	}
}

// pgpRotate implements `--maintenance pgp rotate` (AI.md PART 11 "Rotate").
func pgpRotate(conn *sql.DB, configDir, appName, securityContact string, cfg *config.AppConfig, logMgr *applog.Manager) {
	secret, err := security.GetOrCreateSecret(conn, security.SecretInstallationSecret)
	if err != nil {
		log.Printf("pgp rotate: load installation secret: %v", err)
		os.Exit(exSoftware)
	}

	oldRec, err := pgp.ActiveRecord(conn)
	if err != nil {
		log.Printf("pgp rotate: load active record: %v", err)
		os.Exit(exSoftware)
	}

	var oldEntity *openpgp.Entity
	if oldRec != nil {
		if oldArmor, loadErr := pgp.LoadPrivateArmor(configDir, secret); loadErr == nil {
			oldEntity, _ = pgp.ParsePrivate(oldArmor)
		} else {
			log.Printf("Warning: pgp rotate: could not load previous private key for cross-signing: %v", loadErr)
		}
	}

	kp, err := pgp.Rotate(appName, securityContact, oldEntity)
	if err != nil {
		log.Printf("pgp rotate: %v", err)
		os.Exit(exSoftware)
	}
	if err := pgp.Save(configDir, kp, secret); err != nil {
		log.Printf("pgp rotate: save: %v", err)
		os.Exit(exIoErr)
	}
	if err := pgp.InsertRecord(conn, kp.Fingerprint, kp.CreatedAt, kp.ExpiresAt); err != nil {
		log.Printf("pgp rotate: record: %v", err)
		os.Exit(exSoftware)
	}
	if oldRec != nil {
		if err := pgp.MarkRotated(conn, oldRec.Fingerprint); err != nil {
			log.Printf("Warning: pgp rotate: mark old key rotated: %v", err)
		}
	}
	if logMgr != nil {
		logMgr.WriteAuditEvent("", "security.pgp_key_rotated", "security", "info", "success", "", map[string]any{
			"fingerprint":     kp.Fingerprint,
			"previous_key_fp": oldRecFingerprint(oldRec),
		})
	}
	fmt.Printf("Rotated PGP keypair: %s\n", kp.Fingerprint)
	fmt.Printf("Expires: %s\n", kp.ExpiresAt.Format("2006-01-02"))
	fmt.Printf("Previous key remains valid for %s (grace period) for in-flight reports.\n", pgp.RotationGrace)

	if cfg.Web.Security.PublishPGPKey && len(cfg.Web.Security.Keyservers) > 0 {
		publishToKeyservers(conn, configDir, kp.Fingerprint, kp.PublicArmor, cfg.Web.Security.Keyservers)
	}
}

// oldRecFingerprint safely extracts a fingerprint from a possibly-nil record.
func oldRecFingerprint(rec *pgp.Record) string {
	if rec == nil {
		return ""
	}
	return rec.Fingerprint
}

// publishToKeyservers submits the public key to every configured keyserver
// and prints per-host results.
func publishToKeyservers(conn *sql.DB, configDir, fingerprint, publicArmor string, keyservers []string) {
	for _, r := range pgp.Publish(conn, fingerprint, publicArmor, keyservers) {
		if r.Err != nil {
			log.Printf("pgp publish: %s: %v", r.Host, r.Err)
		} else {
			fmt.Printf("Published to %s\n", r.Host)
		}
	}

	// Mirror the DB's keyservers_published map to {config_dir}/security/keyservers.state
	// (AI.md PART 11 "Backup Integration (PART 21)") so a backup taken after
	// this publish carries the state needed to avoid double-submitting on restore.
	if rec, err := pgp.ActiveRecord(conn); err == nil && rec != nil {
		if err := pgp.WriteKeyserversState(configDir, rec.Fingerprint, rec.KeyserversPublished); err != nil {
			log.Printf("pgp publish: write keyservers state: %v", err)
		}
	}
}

// pgpPublishKeyservers implements `--maintenance pgp publish` (AI.md PART 11
// "Publish to keyservers"), republishing the active key on demand.
func pgpPublishKeyservers(conn *sql.DB, configDir string, cfg *config.AppConfig, logMgr *applog.Manager) {
	rec, err := pgp.ActiveRecord(conn)
	if err != nil {
		log.Printf("pgp publish: %v", err)
		os.Exit(exSoftware)
	}
	if rec == nil {
		fmt.Println("No active PGP keypair; run --maintenance pgp generate first.")
		os.Exit(exConfig)
	}
	if len(cfg.Web.Security.Keyservers) == 0 {
		fmt.Println("No keyservers configured (web.security.keyservers).")
		return
	}
	pubArmor, err := pgp.LoadPublic(configDir)
	if err != nil {
		log.Printf("pgp publish: load public key: %v", err)
		os.Exit(exIoErr)
	}
	publishToKeyservers(conn, configDir, rec.Fingerprint, pubArmor, cfg.Web.Security.Keyservers)
	if logMgr != nil {
		logMgr.WriteAuditEvent("", "security.pgp_key_published", "security", "info", "success", "", map[string]any{
			"fingerprint": rec.Fingerprint,
		})
	}
}

// pgpExportPublic implements `--maintenance pgp export public [path]`.
func pgpExportPublic(configDir, path string) {
	pubArmor, err := pgp.LoadPublic(configDir)
	if err != nil {
		log.Printf("pgp export public: %v", err)
		os.Exit(exIoErr)
	}
	if path == "" {
		fmt.Print(pubArmor)
		return
	}
	if err := os.WriteFile(path, []byte(pubArmor), 0o644); err != nil {
		log.Printf("pgp export public: write %s: %v", path, err)
		os.Exit(exIoErr)
	}
	fmt.Printf("Public key written to %s\n", path)
}

// pgpExportPrivate implements `--maintenance pgp export private <path>`
// (AI.md PART 11 "Export private"): typed confirmation, 1/hour/operator
// rate limit, a logged reason, mode-0600 output, and an audit event
// recording the operator's typed reason.
func pgpExportPrivate(conn *sql.DB, configDir, path string, logMgr *applog.Manager) {
	if !requireTypedConfirmation("EXPORT PRIVATE KEY",
		"WARNING: this exposes the raw, decrypted PGP private key.\n"+
			"Type EXPORT PRIVATE KEY to confirm: ") {
		fmt.Println("Export cancelled.")
		return
	}

	if wait := pgpExportRateLimitRemaining(configDir); wait > 0 {
		fmt.Printf("Rate limited: private key export is allowed once per hour. Try again in %s.\n", wait.Round(time.Second))
		os.Exit(exNoPerm)
	}

	fmt.Print("Reason for export (required, recorded to audit.log): ")
	reader := bufio.NewReader(os.Stdin)
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)
	if reason == "" {
		fmt.Println("A reason is required for this sensitive operation.")
		os.Exit(exUsage)
	}

	secret, err := security.GetOrCreateSecret(conn, security.SecretInstallationSecret)
	if err != nil {
		log.Printf("pgp export private: load installation secret: %v", err)
		os.Exit(exSoftware)
	}
	privArmor, err := pgp.LoadPrivateArmor(configDir, secret)
	if err != nil {
		log.Printf("pgp export private: %v", err)
		os.Exit(exIoErr)
	}
	if err := os.WriteFile(path, []byte(privArmor), 0o600); err != nil {
		log.Printf("pgp export private: write %s: %v", path, err)
		os.Exit(exIoErr)
	}
	pgpMarkExportTimestamp(configDir)

	rec, _ := pgp.ActiveRecord(conn)
	if logMgr != nil {
		logMgr.WriteAuditEvent("", "security.private_key_exported", "security", "warn", "success", "", map[string]any{
			"fingerprint": oldRecFingerprint(rec),
			"path":        path,
			"reason":      reason,
		})
	}
	fmt.Printf("Private key exported to %s (mode 0600). This action has been logged.\n", path)
}

// pgpImport implements `--maintenance pgp import <file>` (AI.md PART 11
// "Import"): parses the armored private key, warns (with operator override)
// if its identity doesn't match the project's expected identity, then
// persists it as the active keypair.
func pgpImport(conn *sql.DB, configDir, file, appName, securityContact string, logMgr *applog.Manager) {
	if !requireTypedConfirmation("IMPORT PRIVATE KEY",
		"WARNING: this replaces the current PGP keypair.\n"+
			"Type IMPORT PRIVATE KEY to confirm: ") {
		fmt.Println("Import cancelled.")
		return
	}

	raw, err := os.ReadFile(file)
	if err != nil {
		log.Printf("pgp import: read %s: %v", file, err)
		os.Exit(exIoErr)
	}
	entity, err := pgp.ParsePrivate(string(raw))
	if err != nil {
		log.Printf("pgp import: %v", err)
		os.Exit(exSoftware)
	}

	expectedIdentity := pgp.Identity(appName, securityContact)
	matched := false
	for name := range entity.Identities {
		if name == expectedIdentity {
			matched = true
			break
		}
	}
	if !matched {
		fmt.Printf("Warning: imported key identity does not match expected %q.\n", expectedIdentity)
		if !requireTypedConfirmation("OVERRIDE", "Type OVERRIDE to import anyway: ") {
			fmt.Println("Import cancelled.")
			return
		}
	}

	pubArmor, err := pgp.ArmorPublic(entity)
	if err != nil {
		log.Printf("pgp import: %v", err)
		os.Exit(exSoftware)
	}

	secret, err := security.GetOrCreateSecret(conn, security.SecretInstallationSecret)
	if err != nil {
		log.Printf("pgp import: load installation secret: %v", err)
		os.Exit(exSoftware)
	}

	fingerprint := pgp.Fingerprint(entity)
	createdAt := entity.PrimaryKey.CreationTime
	kp := &pgp.Keypair{
		Entity:       entity,
		Fingerprint:  fingerprint,
		PublicArmor:  pubArmor,
		PrivateArmor: string(raw),
		CreatedAt:    createdAt,
		ExpiresAt:    createdAt.Add(pgp.KeyLifetime),
	}
	if err := pgp.Save(configDir, kp, secret); err != nil {
		log.Printf("pgp import: save: %v", err)
		os.Exit(exIoErr)
	}
	if err := pgp.InsertRecord(conn, kp.Fingerprint, kp.CreatedAt, kp.ExpiresAt); err != nil {
		log.Printf("pgp import: record: %v", err)
		os.Exit(exSoftware)
	}
	if logMgr != nil {
		logMgr.WriteAuditEvent("", "security.pgp_key_imported", "security", "warn", "success", "", map[string]any{
			"fingerprint": kp.Fingerprint,
			"source_file": file,
		})
	}
	fmt.Printf("Imported PGP keypair: %s\n", kp.Fingerprint)
}

// pgpDelete implements `--maintenance pgp delete` (AI.md PART 11 "Delete"):
// removes the key files, marks the DB record revoked, and flips
// web.security.publish_pgp_key off so security.txt stops advertising it.
func pgpDelete(conn *sql.DB, configDir string, cfg *config.AppConfig, logMgr *applog.Manager) {
	if !requireTypedConfirmation("DELETE PGP KEY",
		"WARNING: this permanently deletes the PGP keypair.\n"+
			"In-flight encrypted security reports become un-decryptable.\n"+
			"Type DELETE PGP KEY to confirm: ") {
		fmt.Println("Delete cancelled.")
		return
	}

	rec, _ := pgp.ActiveRecord(conn)
	if err := pgp.Delete(configDir); err != nil {
		log.Printf("pgp delete: %v", err)
		os.Exit(exIoErr)
	}
	if rec != nil {
		if err := pgp.MarkRevoked(conn, rec.Fingerprint); err != nil {
			log.Printf("Warning: pgp delete: mark revoked: %v", err)
		}
	}

	cfg.Web.Security.PublishPGPKey = false
	if err := config.SaveConfigToFile(); err != nil {
		log.Printf("Warning: pgp delete: failed to persist publish_pgp_key=false: %v", err)
	}

	if logMgr != nil {
		logMgr.WriteAuditEvent("", "security.pgp_key_deleted", "security", "warn", "success", "", map[string]any{
			"fingerprint": oldRecFingerprint(rec),
		})
	}
	fmt.Println("PGP keypair deleted. web.security.publish_pgp_key set to false.")
}

// handleSecretMaintenance implements `--maintenance secret rotate <name>`
// (AI.md PART 5 "Sensitive Operations" table and PART 11 "Secret Rotation").
// Only installation_secret and encryption_key are operator-rotatable;
// cookie_signing_key and csrf_token_secret are auto-rotated only.
func handleSecretMaintenance(args []string, configDir, logsDir string, cfg *config.AppConfig) {
	if len(args) < 2 || args[0] != "rotate" {
		fmt.Println("Usage: ipgaze --maintenance secret rotate <installation_secret|encryption_key>")
		os.Exit(exUsage)
	}

	name := args[1]
	switch name {
	case "installation_secret", "encryption_key":
		// valid, handled below
	case "cookie_signing_key", "csrf_token_secret":
		fmt.Printf("%s is auto-rotated only and cannot be rotated manually.\n", name)
		os.Exit(exUsage)
	default:
		fmt.Printf("Unknown secret: %s\n", name)
		fmt.Println("Valid names: installation_secret, encryption_key")
		os.Exit(exUsage)
	}

	if !requireOperatorAuth(cfg, "This is a sensitive secret-rotation operation. Enter operator token to confirm: ") {
		fmt.Println("Authorization required: run as root/administrator, or provide a valid operator token.")
		os.Exit(exNoPerm)
	}
	confirmPhrase := "ROTATE " + strings.ToUpper(name)
	if !requireTypedConfirmation(confirmPhrase,
		fmt.Sprintf("WARNING: this rotates %s and re-encrypts dependent data.\nType %s to confirm: ", name, confirmPhrase)) {
		fmt.Println("Rotation cancelled.")
		return
	}

	dirs := paths.GetDirectories()
	conn, err := openMaintenanceDB(cfg, dirs)
	if err != nil {
		log.Printf("secret rotate: failed to open database: %v", err)
		os.Exit(exIoErr)
	}
	defer conn.Close()

	logMgr, logMgrErr := applog.NewManager(logsDir, buildLogConfig(cfg))
	if logMgrErr != nil {
		log.Printf("Warning: secret rotate: failed to open audit log: %v", logMgrErr)
		logMgr = nil
	} else {
		defer logMgr.Close()
	}

	switch name {
	case "installation_secret":
		rotateInstallationSecret(conn, configDir, logMgr)
	case "encryption_key":
		rotateEncryptionKey(configDir, cfg, logMgr)
	}
}

// rotateInstallationSecret implements the installation_secret branch of
// `--maintenance secret rotate` (AI.md PART 11): rotates the app_secrets row,
// re-encrypts the PGP private key with the new value, and grants the old
// value a 7-day grace window for in-flight validation.
func rotateInstallationSecret(conn *sql.DB, configDir string, logMgr *applog.Manager) {
	oldSecret, err := security.GetOrCreateSecret(conn, security.SecretInstallationSecret)
	if err != nil {
		log.Printf("secret rotate installation_secret: load current: %v", err)
		os.Exit(exSoftware)
	}
	if err := security.RotateSecret(conn, security.SecretInstallationSecret); err != nil {
		log.Printf("secret rotate installation_secret: rotate: %v", err)
		os.Exit(exSoftware)
	}
	newSecret, err := security.GetOrCreateSecret(conn, security.SecretInstallationSecret)
	if err != nil {
		log.Printf("secret rotate installation_secret: load new: %v", err)
		os.Exit(exSoftware)
	}

	if err := pgp.ReencryptPrivateKey(configDir, oldSecret, newSecret); err != nil {
		log.Printf("secret rotate installation_secret: re-encrypt PGP private key: %v", err)
		os.Exit(exSoftware)
	}

	if logMgr != nil {
		logMgr.WriteAuditEvent("", "security.installation_secret_rotated", "security", "warn", "success", "", map[string]any{
			"grace_period": "7d",
		})
	}
	fmt.Println("Rotated installation_secret.")
	fmt.Println("PGP private key re-encrypted with the new value.")
	fmt.Println("Previous value remains valid for 7 days (grace period) for in-flight validation.")
}

// rotateEncryptionKey implements the encryption_key branch of
// `--maintenance secret rotate` (AI.md PART 11): generates a new at-rest
// encryption key, re-encrypts DNS-01 provider credentials (the only
// currently-implemented data encrypted under this key), keeps the previous
// key valid for a 30-day grace window, and persists everything to server.yml.
func rotateEncryptionKey(configDir string, cfg *config.AppConfig, logMgr *applog.Manager) {
	oldKeyB64 := cfg.Server.Security.EncryptionKey
	oldKey, err := base64.StdEncoding.DecodeString(oldKeyB64)
	if err != nil {
		log.Printf("secret rotate encryption_key: decode current key: %v", err)
		os.Exit(exSoftware)
	}

	newKeyB64, err := generateEncryptionKey()
	if err != nil {
		log.Printf("secret rotate encryption_key: generate: %v", err)
		os.Exit(exSoftware)
	}
	newKey, err := base64.StdEncoding.DecodeString(newKeyB64)
	if err != nil {
		log.Printf("secret rotate encryption_key: decode new key: %v", err)
		os.Exit(exSoftware)
	}

	reencryptedDNS, err := ssl.ReencryptDNSCredentialsEncrypted(
		cfg.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted, oldKey, newKey)
	if err != nil {
		log.Printf("secret rotate encryption_key: re-encrypt dns_credentials: %v", err)
		os.Exit(exSoftware)
	}

	cfg.Server.Security.PreviousEncryptionKey = oldKeyB64
	cfg.Server.Security.PreviousEncryptionKeyUntil = time.Now().Add(30 * 24 * time.Hour).Unix()
	cfg.Server.Security.EncryptionKey = newKeyB64
	cfg.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted = reencryptedDNS

	if err := config.SaveConfigToFile(); err != nil {
		log.Printf("secret rotate encryption_key: save config: %v", err)
		os.Exit(exIoErr)
	}

	if logMgr != nil {
		logMgr.WriteAuditEvent("", "security.encryption_key_rotated", "security", "warn", "success", "", map[string]any{
			"grace_period": "30d",
		})
	}
	fmt.Println("Rotated encryption_key.")
	fmt.Println("DNS-01 provider credentials re-encrypted with the new value.")
	fmt.Println("Previous value remains valid for 30 days (grace period).")
}

func handleMaintenanceCommand(cmd, configDir, dataDir, logsDir, configPath string, cfg *config.AppConfig, includeSSL, includeData bool) {
	args := flag.Args()
	dirs := paths.GetDirectories()

	switch cmd {
	case "--help":
		fmt.Println(`Maintenance commands: backup, restore, update, mode, setup, pgp, secret, token, data, compliance

Backup:
  --maintenance backup [file]     Create a backup archive
      --include-ssl                Include SSL/TLS private keys (default: excluded)
      --include-data               Include the full data directory (default: excluded)

  By default a backup contains only server.yml, server.db, template/, and
  theme/ — it is safe to move off-host without exposing credentials.

  Examples:
    ipgaze --maintenance backup
    ipgaze --maintenance backup /path/to/backup.tar.gz
    ipgaze --include-ssl --maintenance backup
    ipgaze --include-ssl --include-data --maintenance backup

Restore:
  --maintenance restore <file>    Restore from a backup archive

  Archives created without --include-ssl or --include-data are partial by
  design: restoring one leaves the existing SSL certs and/or data directory
  untouched rather than failing.

  Example:
    ipgaze --maintenance restore /path/to/backup.tar.gz`)
		return
	case "backup":
		backupFile := ""
		if len(args) > 0 {
			backupFile = args[0]
		} else {
			backupDir := paths.GetBackupDir("", dataDir)
			if err := os.MkdirAll(backupDir, 0755); err != nil {
				log.Printf("Failed to create backup directory: %v", err)
				os.Exit(exCantCreat)
			}
			timestamp := time.Now().Format("2006-01-02_150405")
			backupFile = filepath.Join(backupDir, fmt.Sprintf("ipgaze_backup_%s.tar.gz", timestamp))
		}
		cliLogMgr, cliLogErr := applog.NewManager(logsDir, buildLogConfig(cfg))
		if cliLogErr != nil {
			cliLogMgr = nil
		} else {
			defer cliLogMgr.Close()
		}
		if err := maintenanceBackup(cfg, configDir, dataDir, dirs.DB, backupFile, includeSSL, includeData, true, cliLogMgr); err != nil {
			log.Printf("Backup failed: %v", err)
			os.Exit(exIoErr)
		}
	case "restore":
		if len(args) == 0 {
			fmt.Println("Usage: ipgaze --maintenance restore <backup-file>")
			os.Exit(exUsage)
		}
		restoreLogMgr, restoreLogErr := applog.NewManager(logsDir, buildLogConfig(cfg))
		if restoreLogErr != nil {
			restoreLogMgr = nil
		} else {
			defer restoreLogMgr.Close()
		}
		maintenanceRestore(args[0], configDir, dataDir, dirs.DB, cfg, dirs, restoreLogMgr)
	case "update":
		// --maintenance update is an alias for --update yes per AI.md PART 22
		if cfg == nil {
			loaded, loadErr := config.LoadConfigFromFile(configPath)
			if loadErr != nil {
				log.Printf("Failed to load config from %s: %v", configPath, loadErr)
				os.Exit(exConfig)
			}
			cfg = loaded
		}
		handleUpdateCommand("yes", cfg)
	case "mode":
		maintenanceMode(args, cfg)
	case "setup":
		maintenanceSetup(configPath, cfg, dirs)
	case "pgp":
		handlePGPMaintenance(args, configDir, logsDir, configPath, cfg)
	case "secret":
		handleSecretMaintenance(args, configDir, logsDir, cfg)
	case "token":
		maintenanceToken(args, cfg, logsDir, dirs)
	case "data":
		maintenanceData(args, cfg, logsDir, dirs)
	case "compliance":
		maintenanceCompliance(args, cfg)
	default:
		fmt.Printf("Unknown maintenance command: %s\n", cmd)
		fmt.Println("Available commands: backup, restore, update, mode, setup, pgp, secret, token, data, compliance")
		os.Exit(exUsage)
	}
}

// isDatabaseEmpty reports whether this looks like a fresh install — no audit
// log entries and no API tokens issued yet. Used to gate first-run bypasses
// for setup/restore per AI.md PART 5 "Sensitive Operations" authorization
// flowcharts (isDatabaseEmpty()).
func isDatabaseEmpty(conn *sql.DB) bool {
	var auditCount, tokenCount int
	// AI.md PART 10 "Query Timeouts": simple SELECTs get a 5-second budget.
	ctx, cancel := context.WithTimeout(context.Background(), simpleSelectTimeout)
	defer cancel()
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log").Scan(&auditCount); err != nil {
		return false
	}
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_tokens").Scan(&tokenCount); err != nil {
		return false
	}
	return auditCount == 0 && tokenCount == 0
}

// maintenanceMode implements `--maintenance mode [production|development]` per
// AI.md PART 5 "Mode change authorization flow": read-only when no argument is
// given; changing the mode requires `server.token` OR root (requireOperatorAuth).
func maintenanceMode(args []string, cfg *config.AppConfig) {
	if len(args) == 0 {
		mode := cfg.Server.Mode
		if mode == "" {
			mode = "production"
		}
		fmt.Printf("Current mode: %s\n", mode)
		return
	}

	if !requireOperatorAuth(cfg, "Changing the application mode requires authorization. Enter operator token to confirm: ") {
		fmt.Println("Authorization required: run as root/administrator, or provide a valid operator token.")
		os.Exit(exNoPerm)
	}

	newMode := args[0]
	if newMode != "production" && newMode != "development" {
		fmt.Printf("Invalid mode: %s\n", newMode)
		fmt.Println("Valid modes: production, development")
		os.Exit(exUsage)
	}
	cfg.Server.Mode = newMode
	if err := config.SaveConfigToFile(); err != nil {
		log.Printf("Failed to save config: %v", err)
		os.Exit(exIoErr)
	}
	fmt.Printf("Application mode set to: %s\n", newMode)
}

// maintenanceSetup implements `--maintenance setup` per AI.md PART 5 "Setup
// authorization flow": allowed on first-run (empty database) or when
// root/elevated (with typed confirmation); otherwise rejected with the exact
// operator-facing message from AI.md.
func maintenanceSetup(configPath string, cfg *config.AppConfig, dirs paths.Directories) {
	conn, err := openMaintenanceDB(cfg, dirs)
	if err != nil {
		log.Printf("setup: failed to open database: %v", err)
		os.Exit(exIoErr)
	}
	firstRun := isDatabaseEmpty(conn)
	conn.Close()

	if !firstRun && !isElevated() {
		fmt.Println("Setup already completed. To reconfigure:")
		fmt.Println(" 1. Edit server.yml directly and restart the server")
		fmt.Printf(" 2. Run as root: sudo %s --maintenance setup\n", projectName)
		os.Exit(exNoPerm)
	}
	if !firstRun {
		if !requireTypedConfirmation("RESET SETUP", "Running as root will reset server configuration to defaults.\nType RESET SETUP to confirm: ") {
			fmt.Println("Setup cancelled.")
			return
		}
	}

	fmt.Println("IPGaze Initial Setup")
	fmt.Println("====================")
	token := cfg.Server.Token
	def := config.DefaultConfig()
	def.Server.Token = token
	*cfg = *def
	if err := config.SaveConfigToFile(); err != nil {
		log.Printf("Failed to save config: %v", err)
		os.Exit(exIoErr)
	}
	fmt.Printf("Config: %s\n", configPath)
	fmt.Printf("Port: %s\n", cfg.Server.Port)
	fmt.Printf("Mode: %s\n", cfg.Server.Mode)
	fmt.Println("Setup complete. Configuration reset to defaults.")
}

// maintenanceToken implements `--maintenance token <list|revoke>` per AI.md
// PART 11 "Operator revocation" — operator-only via CLI (server.token OR root).
func maintenanceToken(args []string, cfg *config.AppConfig, logsDir string, dirs paths.Directories) {
	if len(args) == 0 {
		fmt.Println("Usage: ipgaze --maintenance token <list|revoke> [prefix]")
		os.Exit(exUsage)
	}
	if !requireOperatorAuth(cfg, "Token management requires authorization. Enter operator token to confirm: ") {
		fmt.Println("Authorization required: run as root/administrator, or provide a valid operator token.")
		os.Exit(exNoPerm)
	}

	conn, err := openMaintenanceDB(cfg, dirs)
	if err != nil {
		log.Printf("token: failed to open database: %v", err)
		os.Exit(exIoErr)
	}
	defer conn.Close()

	switch args[0] {
	case "list":
		maintenanceTokenList(conn)
	case "revoke":
		if len(args) < 2 {
			fmt.Println("Usage: ipgaze --maintenance token revoke <prefix>")
			os.Exit(exUsage)
		}
		maintenanceTokenRevoke(conn, args[1], logsDir, cfg)
	default:
		fmt.Printf("Unknown token command: %s\n", args[0])
		os.Exit(exUsage)
	}
}

// maintenanceTokenList prints active/expired/revoked api_tokens rows.
func maintenanceTokenList(conn *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), simpleSelectTimeout)
	defer cancel()
	rows, err := conn.QueryContext(ctx, `SELECT token_prefix, resource_type, resource_id, created_at, expires_at, revoked_at
        FROM api_tokens ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("token list: query failed: %v", err)
		os.Exit(exIoErr)
	}
	defer rows.Close()

	fmt.Printf("%-12s %-12s %-24s %-20s %-10s\n", "PREFIX", "TYPE", "RESOURCE", "CREATED", "STATUS")
	count := 0
	for rows.Next() {
		var prefix, resType, resID string
		var createdAt int64
		var expiresAt, revokedAt sql.NullInt64
		if err := rows.Scan(&prefix, &resType, &resID, &createdAt, &expiresAt, &revokedAt); err != nil {
			continue
		}
		status := "active"
		if revokedAt.Valid {
			status = "revoked"
		} else if expiresAt.Valid && expiresAt.Int64 < time.Now().Unix() {
			status = "expired"
		}
		fmt.Printf("%-12s %-12s %-24s %-20s %-10s\n",
			prefix, resType, resID, time.Unix(createdAt, 0).Format(time.RFC3339), status)
		count++
	}
	if count == 0 {
		fmt.Println("No tokens found.")
	}
}

// maintenanceTokenRevoke revokes every active api_tokens row matching prefix.
func maintenanceTokenRevoke(conn *sql.DB, prefix, logsDir string, cfg *config.AppConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), writeQueryTimeout)
	defer cancel()
	res, err := conn.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ?, revoked_reason = ?
        WHERE token_prefix = ? AND revoked_at IS NULL`,
		time.Now().Unix(), "revoked via --maintenance token revoke", prefix)
	if err != nil {
		log.Printf("token revoke: update failed: %v", err)
		os.Exit(exIoErr)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		fmt.Printf("No active token found with prefix %q.\n", prefix)
		return
	}

	logMgr, logMgrErr := applog.NewManager(logsDir, buildLogConfig(cfg))
	if logMgrErr == nil {
		logMgr.WriteAuditEvent("", "cli.token_revoked", "security", "warn", "success", "", map[string]any{
			"token_prefix": prefix,
		})
		logMgr.Close()
	}
	fmt.Printf("Token %s revoked.\n", prefix)
}

// maintenanceData implements `--maintenance data <export|delete>`. This
// project has no per-user PII table (see AI.md PART 21), so export/delete
// operate on the operational data that can carry PII: rate_limits and
// audit_log rows (IP addresses), plus the configured privacy policy.
func maintenanceData(args []string, cfg *config.AppConfig, logsDir string, dirs paths.Directories) {
	if len(args) == 0 {
		fmt.Println("Usage: ipgaze --maintenance data <export|delete>")
		os.Exit(exUsage)
	}
	if !requireOperatorAuth(cfg, "Data operations require authorization. Enter operator token to confirm: ") {
		fmt.Println("Authorization required: run as root/administrator, or provide a valid operator token.")
		os.Exit(exNoPerm)
	}

	conn, err := openMaintenanceDB(cfg, dirs)
	if err != nil {
		log.Printf("data: failed to open database: %v", err)
		os.Exit(exIoErr)
	}
	defer conn.Close()

	switch args[0] {
	case "export":
		maintenanceDataExport(conn, cfg)
	case "delete":
		maintenanceDataDelete(conn, logsDir, cfg)
	default:
		fmt.Printf("Unknown data command: %s\n", args[0])
		os.Exit(exUsage)
	}
}

// maintenanceDataExport prints a JSON disclosure of the configured privacy
// policy plus a row-count inventory of every table that may hold operator
// or visitor data, per AI.md PART 21 GDPR/CCPA "data export" behaviors.
func maintenanceDataExport(conn *sql.DB, cfg *config.AppConfig) {
	tables := []string{"config", "rate_limits", "audit_log", "scheduler_history", "backups", "api_tokens", "pgp_keypairs"}
	counts := map[string]int{}
	ctx, cancel := context.WithTimeout(context.Background(), simpleSelectTimeout)
	defer cancel()
	for _, t := range tables {
		var n int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+t).Scan(&n); err == nil { //nolint:gosec
			counts[t] = n
		}
	}

	report := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"privacy_policy": map[string]any{
			"data_sold":             cfg.Server.Privacy.Data.Sold,
			"data_stored_on_server": cfg.Server.Privacy.Data.StoredOnServer,
			"retention_period":      cfg.Server.Privacy.Retention.Period,
			"retention_export":      cfg.Server.Privacy.Retention.ExportAvailable,
			"retention_deletion":    cfg.Server.Privacy.Retention.DeletionAvailable,
		},
		"table_row_counts": counts,
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Printf("data export: marshal failed: %v", err)
		os.Exit(exSoftware)
	}
	fmt.Println(string(out))
}

// maintenanceDataDelete purges rate_limits and audit_log rows (the tables
// that can carry visitor/operator IP addresses), preserving config, PGP
// keys, and issued tokens. Destructive — requires typed confirmation and is
// itself audit-logged (to a fresh log entry recorded before the purge).
func maintenanceDataDelete(conn *sql.DB, logsDir string, cfg *config.AppConfig) {
	if !requireTypedConfirmation("DELETE OPERATIONAL DATA",
		"WARNING: this permanently deletes rate-limit and audit-log history.\n"+
			"Configuration, PGP keys, and issued tokens are preserved.\n"+
			"Type DELETE OPERATIONAL DATA to confirm: ") {
		fmt.Println("Data delete cancelled.")
		return
	}

	logMgr, logMgrErr := applog.NewManager(logsDir, buildLogConfig(cfg))
	if logMgrErr == nil {
		logMgr.WriteAuditEvent("", "cli.data_deleted", "security", "warn", "success", "", map[string]any{
			"tables": []string{"rate_limits", "audit_log"},
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeQueryTimeout)
	defer cancel()
	if _, err := conn.ExecContext(ctx, "DELETE FROM rate_limits"); err != nil {
		log.Printf("data delete: failed to clear rate_limits: %v", err)
		os.Exit(exIoErr)
	}
	if _, err := conn.ExecContext(ctx, "DELETE FROM audit_log"); err != nil {
		log.Printf("data delete: failed to clear audit_log: %v", err)
		os.Exit(exIoErr)
	}
	if logMgrErr == nil {
		logMgr.Close()
	}
	fmt.Println("Operational data (rate_limits, audit_log) deleted.")
}

// maintenanceCompliance implements `--maintenance compliance report` per
// AI.md PART 21: a read-only summary of what is actually configured (this
// project has no per-standard GDPR/HIPAA/SOC2/... flags — compliance is
// configured entirely in server.yml, per AI.md's closing note on PART 21).
func maintenanceCompliance(args []string, cfg *config.AppConfig) {
	if len(args) > 0 && args[0] != "report" {
		fmt.Printf("Unknown compliance command: %s\n", args[0])
		fmt.Println("Usage: ipgaze --maintenance compliance report")
		os.Exit(exUsage)
	}

	fmt.Println("IPGaze Compliance Report")
	fmt.Println("========================")
	fmt.Printf("Compliance mode enabled:  %t\n", cfg.Server.Compliance.Enabled)
	fmt.Printf("Data sold to third parties: %t\n", cfg.Server.Privacy.Data.Sold)
	fmt.Printf("Data stored on server:      %t\n", cfg.Server.Privacy.Data.StoredOnServer)
	fmt.Printf("Retention period:  %s\n", cfg.Server.Privacy.Retention.Period)
	fmt.Printf("Retention export:  %t\n", cfg.Server.Privacy.Retention.ExportAvailable)
	fmt.Printf("Retention deletion: %t\n", cfg.Server.Privacy.Retention.DeletionAvailable)
	fmt.Printf("Consent banner shown until acknowledged: %t\n", cfg.Server.Privacy.Consent.ShowUntilAcknowledged)
	fmt.Printf("TLS enabled:       %t\n", cfg.Server.SSL.Enabled)
	fmt.Printf("Let's Encrypt:     %t\n", cfg.Server.SSL.LetsEncrypt.Enabled)
	fmt.Printf("PGP key published: %t\n", cfg.Web.Security.PublishPGPKey)
	fmt.Printf("Audit logging level: %s\n", cfg.Server.Logging.Level)
}

// scheduleFor returns the configured schedule override if non-empty, otherwise the default.
func scheduleFor(defaultSched string, taskCfg config.TaskScheduleConfig) string {
	if taskCfg.Schedule != "" {
		return taskCfg.Schedule
	}
	return defaultSched
}

// enabledFor returns the configured enabled override if set, otherwise the default.
func enabledFor(defaultEnabled bool, taskCfg config.TaskScheduleConfig) bool {
	if taskCfg.Enabled != nil {
		return *taskCfg.Enabled
	}
	return defaultEnabled
}

// Maintenance functions

// maintenanceBackup creates a verified backup archive per AI.md PART 21.
// It builds manifest.json and the tar.gz entirely in memory, encrypts it with
// AES-256-GCM when a backup password is configured (or required by compliance
// mode), writes the result to disk, then runs all 7 required verification
// checks. Returns an error on any failure; never calls log.Fatalf.
// interactive controls whether a password may be prompted for on the
// controlling terminal — scheduled/background backups must pass false.
func maintenanceBackup(cfg *config.AppConfig, configDir, dataDir, dbDir, backupFile string, includeSSL, includeData, interactive bool, logMgr *applog.Manager) (backupErr error) {
	fmt.Printf("Creating backup: %s\n", backupFile)

	// AI.md PART 21 requires a backup.failed audit event for every failed
	// backup. Emitted from a defer so no error path can skip it, and skipped
	// for backup.verification_failed which already records its own event.
	defer func() {
		if backupErr == nil || logMgr == nil {
			return
		}
		if strings.HasPrefix(backupErr.Error(), "backup verification failed") {
			return
		}
		logMgr.WriteAuditEvent("", "backup.failed", "backup", "error", "failure", "", map[string]any{
			"filename": filepath.Base(backupFile),
			"error":    backupErr.Error(),
		})
	}()

	password, err := resolveBackupEncryptionPassword(cfg, interactive)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	encrypted := password != ""

	layout := backupArchiveLayout{
		configDir:   configDir,
		dataDir:     dataDir,
		dbDir:       dbDir,
		includeSSL:  includeSSL,
		includeData: includeData,
	}

	// Build manifest before archiving. checksum and contents are filled in by
	// buildBackupArchive from what this layout actually includes.
	now := time.Now().UTC()
	manifest := map[string]interface{}{
		"version":     Version,
		"created_at":  now.Format(time.RFC3339),
		"created_by":  "scheduler",
		"app_version": Version,
		"encrypted":   encrypted,
	}
	if interactive {
		manifest["created_by"] = "operator"
	}
	if encrypted {
		manifest["encryption_method"] = "AES-256-GCM"
	}

	// Build the tar.gz archive entirely in memory.
	archive, err := buildBackupArchive(manifest, layout)
	if err != nil {
		return fmt.Errorf("backup: build archive: %w", err)
	}

	finalFile := backupFile
	payload := archive
	if encrypted {
		// The unencrypted archive never touches disk — encrypt in memory
		// before the first write.
		enc, encErr := encryptBackupArchive(archive, password)
		if encErr != nil {
			return fmt.Errorf("backup: encrypt: %w", encErr)
		}
		payload = enc
		if !strings.HasSuffix(finalFile, ".enc") {
			finalFile += ".enc"
		}
	}

	if err := os.WriteFile(finalFile, payload, 0o600); err != nil {
		return fmt.Errorf("backup: write archive: %w", err)
	}

	// 7 required verification checks per AI.md PART 21.
	// If any check fails: delete the new backup file, write an audit log
	// entry (level=error), and return an error.
	if verifyErr := verifyBackup(finalFile, password, layout); verifyErr != nil {
		// Best-effort cleanup of the failed backup; verification failure is the real error.
		os.Remove(finalFile) //nolint:errcheck
		if logMgr != nil {
			logMgr.WriteAuditEvent("", "backup.verification_failed", "backup", "error", "failure", "", map[string]any{
				"filename": filepath.Base(finalFile),
				"error":    verifyErr.Error(),
			})
		}
		return fmt.Errorf("backup verification failed: %w", verifyErr)
	}

	info, statErr := os.Stat(finalFile)
	var size int64
	if statErr == nil {
		size = info.Size()
	}
	if logMgr != nil {
		logMgr.WriteAuditEvent("", "backup.created", "backup", "info", "success", "", map[string]any{
			"filename":  filepath.Base(finalFile),
			"size":      size,
			"encrypted": encrypted,
			"verified":  true,
		})
	}

	fmt.Printf("Backup created and verified: %s\n", finalFile)
	return nil
}

// verifyBackup runs all 7 required backup verification checks per AI.md PART 21.
// password is required when backupFile ends in .enc; ignored otherwise.
// Returns the first failing check as an error.
func verifyBackup(backupFile, password string, layout backupArchiveLayout) error {
	// Check 1: file exists
	info, err := os.Stat(backupFile)
	if err != nil {
		return fmt.Errorf("check 1 (file exists): %w", err)
	}

	// Check 2: size > 0
	if info.Size() == 0 {
		return fmt.Errorf("check 2 (size > 0): backup file is empty")
	}

	raw, err := os.ReadFile(backupFile)
	if err != nil {
		return fmt.Errorf("check 3 (checksum): cannot read: %w", err)
	}

	// Check 4: decrypt test — required whenever the file is encrypted.
	archiveBytes := raw
	if strings.HasSuffix(backupFile, ".enc") {
		if password == "" {
			return fmt.Errorf("check 4 (decrypt test): encrypted backup but no password provided")
		}
		decrypted, decErr := decryptBackupArchive(raw, password)
		if decErr != nil {
			return fmt.Errorf("check 4 (decrypt test): %w", decErr)
		}
		archiveBytes = decrypted
	}

	// Check 5: manifest readable — verify the archive contains a readable JSON
	// manifest and capture it so Check 3 can compare its stored checksum.
	gr, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return fmt.Errorf("check 5 (manifest readable): gzip open: %w", err)
	}
	tr := tar.NewReader(gr)
	var manifestBytes []byte
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			gr.Close()
			return fmt.Errorf("check 5 (manifest readable): tar read: %w", terr)
		}
		if strings.HasSuffix(hdr.Name, ".json") {
			buf, rerr := io.ReadAll(tr)
			if rerr != nil {
				gr.Close()
				return fmt.Errorf("check 5 (manifest readable): read manifest: %w", rerr)
			}
			manifestBytes = buf
		}
	}
	gr.Close()
	if manifestBytes == nil {
		return fmt.Errorf("check 5 (manifest readable): no manifest.json found in archive")
	}
	var manifest map[string]interface{}
	if jerr := json.Unmarshal(manifestBytes, &manifest); jerr != nil {
		return fmt.Errorf("check 5 (manifest readable): parse manifest: %w", jerr)
	}
	manifestChecksum, _ := manifest["checksum"].(string)

	// Check 6: content extraction test — extract to temp dir and verify non-empty
	tmpDir, err := os.MkdirTemp(os.TempDir(), "ipgaze-backup-verify-")
	if err != nil {
		return fmt.Errorf("check 6 (extraction): create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	if extractErr := extractBackupArchive(archiveBytes, tmpDir); extractErr != nil {
		return fmt.Errorf("check 6 (extraction): %w", extractErr)
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil || len(entries) == 0 {
		return fmt.Errorf("check 6 (extraction): extracted dir is empty")
	}

	// Check 3: SHA-256 checksum — recompute over the extracted config+data
	// file contents and compare against the manifest's stored checksum.
	if manifestChecksum != "" {
		extractedLayout := backupArchiveLayout{
			configDir:   filepath.Join(tmpDir, filepath.Base(layout.configDir)),
			dataDir:     filepath.Join(tmpDir, filepath.Base(layout.dataDir)),
			dbDir:       filepath.Join(tmpDir, "db"),
			includeSSL:  layout.includeSSL,
			includeData: layout.includeData,
		}
		actualChecksum, cksErr := computeBackupContentChecksum(extractedLayout)
		if cksErr != nil {
			return fmt.Errorf("check 3 (checksum): compute: %w", cksErr)
		}
		if actualChecksum != manifestChecksum {
			return fmt.Errorf("check 3 (checksum): mismatch: manifest=%s actual=%s", manifestChecksum, actualChecksum)
		}
	}

	// Check 7: database integrity — find any .db file and run SQLite integrity_check
	var dbErr error
	err = filepath.Walk(tmpDir, func(p string, fi os.FileInfo, e error) error {
		if e != nil || dbErr != nil {
			return nil
		}
		if strings.HasSuffix(p, ".db") {
			integrityCmd := exec.Command("sqlite3", p, "PRAGMA integrity_check;")
			out, err := integrityCmd.Output()
			if err != nil {
				dbErr = fmt.Errorf("sqlite3 not available or db unreadable: %w", err)
				return nil
			}
			if !strings.Contains(strings.TrimSpace(string(out)), "ok") {
				dbErr = fmt.Errorf("integrity_check failed: %s", strings.TrimSpace(string(out)))
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("check 7 (db integrity): walk error: %w", err)
	}
	// Only fail on db integrity if sqlite3 is available and returned a real error
	if dbErr != nil && !strings.Contains(dbErr.Error(), "not available") {
		return fmt.Errorf("check 7 (db integrity): %w", dbErr)
	}

	return nil
}

// maintenanceRestore unpacks a backup archive and replaces configDir, dbDir,
// and (if present in the archive) dataDir. Per AI.md PART 21: restore is
// destructive, requires confirmation, and MUST NOT extract to the filesystem
// root (path traversal risk). Archives created without --include-ssl or
// --include-data are partial by design (PART 21 Backup Contents) — restoring
// one must NOT fail or error; the corresponding existing on-disk content
// (ssl/, data/) is simply left untouched, and the operator is told what was
// and wasn't restored.
func maintenanceRestore(backupFile, configDir, dataDir, dbDir string, cfg *config.AppConfig, dirs paths.Directories, logMgr *applog.Manager) {
	// Authorization per AI.md PART 5 "Restore authorization flow": allowed on
	// first-run (nothing to protect), otherwise requires server.token OR root
	// (requireOperatorAuth already grants root a bypass via isElevated()).
	firstRun := false
	if conn, err := openMaintenanceDB(cfg, dirs); err == nil {
		firstRun = isDatabaseEmpty(conn)
		conn.Close()
	}
	if !firstRun && !requireOperatorAuth(cfg, "This will OVERWRITE all data. Enter operator token to confirm: ") {
		fmt.Println("Restore requires administrator authorization.")
		fmt.Println(" Run as root or provide the operator token.")
		os.Exit(exNoPerm)
	}

	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		log.Printf("Backup file not found: %s", backupFile)
		os.Exit(exIoErr)
	}

	raw, err := os.ReadFile(backupFile)
	if err != nil {
		log.Printf("Restore: cannot read backup file: %v", err)
		os.Exit(exIoErr)
	}

	// Decrypt first if the archive was encrypted per AI.md PART 21.
	// Password is always prompted interactively — there is no password flag.
	archiveBytes := raw
	if strings.HasSuffix(backupFile, ".enc") {
		password, pwErr := promptBackupPassword("Backup password: ")
		if pwErr != nil {
			log.Printf("Restore: %v", pwErr)
			os.Exit(exIoErr)
		}
		decrypted, decErr := decryptBackupArchive(raw, password)
		if decErr != nil {
			log.Printf("Restore: decrypt failed: %v", decErr)
			os.Exit(exIoErr)
		}
		archiveBytes = decrypted
	}

	// Pre-restore verification: confirm archive is readable before destructive step.
	if gr, gzErr := gzip.NewReader(bytes.NewReader(archiveBytes)); gzErr != nil {
		log.Printf("Restore: archive verification failed: %v", gzErr)
		os.Exit(exIoErr)
	} else {
		gr.Close()
	}

	fmt.Printf("WARNING: Restoring from %s will overwrite current data in:\n", backupFile)
	fmt.Printf("  Config: %s\n", configDir)
	fmt.Printf("  Data:   %s\n", dataDir)
	fmt.Print("This operation cannot be undone. Continue? [y/N]: ")
	var answer string
	if _, err := fmt.Scanln(&answer); err != nil || strings.ToLower(strings.TrimSpace(answer)) != "y" {
		fmt.Println("Restore cancelled.")
		return
	}

	// Extract to a controlled temp directory — NEVER to the filesystem root.
	tmpDir, err := os.MkdirTemp("", "ipgaze-restore-*")
	if err != nil {
		log.Printf("Restore: failed to create temp directory: %v", err)
		os.Exit(exOsErr)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Printf("Restoring from backup: %s\n", backupFile)
	if extractErr := extractBackupArchive(archiveBytes, tmpDir); extractErr != nil {
		log.Printf("Restore: extraction failed: %v", extractErr)
		os.Exit(exIoErr)
	}

	// Move extracted config dir to its canonical location. If the archive
	// omitted ssl/ (created without --include-ssl per AI.md PART 21), copy
	// the operator's existing SSL certs forward first so the atomic swap
	// below preserves rather than destroys them.
	extractedConfig := filepath.Join(tmpDir, filepath.Base(configDir))
	sslRestored := false
	if _, err := os.Stat(extractedConfig); err == nil {
		extractedSSL := filepath.Join(extractedConfig, "ssl")
		if _, sslErr := os.Stat(extractedSSL); sslErr == nil {
			sslRestored = true
		} else if existingSSL := filepath.Join(configDir, "ssl"); dirOrFileExists(existingSSL) {
			if copyErr := restoreCopyDir(existingSSL, extractedSSL); copyErr != nil {
				log.Printf("Restore: failed to preserve existing SSL certs: %v", copyErr)
				os.Exit(exIoErr)
			}
		}
		if err := restoreReplaceDir(extractedConfig, configDir); err != nil {
			log.Printf("Restore: failed to restore config: %v", err)
			os.Exit(exIoErr)
		}
	}
	if sslRestored {
		fmt.Println("  ssl:    restored from archive")
	} else {
		fmt.Println("  ssl:    not in archive — existing SSL certs left untouched")
	}

	// Restore the database. Newer archives carry it as a fixed top-level "db"
	// entry (independent of --include-data); older archives nested it inside
	// config/data, which the wholesale restores above already handled.
	extractedDB := filepath.Join(tmpDir, "db")
	dbRestored := false
	if _, err := os.Stat(extractedDB); err == nil {
		if err := restoreReplaceDir(extractedDB, dbDir); err != nil {
			log.Printf("Restore: failed to restore database: %v", err)
			os.Exit(exIoErr)
		}
		dbRestored = true
	}
	if dbRestored {
		fmt.Println("  db:     restored from archive")
	} else {
		fmt.Println("  db:     no dedicated db/ entry in archive — left as extracted via config/data (if any)")
	}

	// Move extracted data dir to its canonical location. Per AI.md PART 21,
	// data/ is only present when the archive was created with --include-data
	// — its absence is expected and must not be treated as an error.
	extractedData := filepath.Join(tmpDir, filepath.Base(dataDir))
	dataRestored := false
	if _, err := os.Stat(extractedData); err == nil {
		if err := restoreReplaceDir(extractedData, dataDir); err != nil {
			log.Printf("Restore: failed to restore data: %v", err)
			os.Exit(exIoErr)
		}
		dataRestored = true
	}
	if dataRestored {
		fmt.Println("  data:   restored from archive")
	} else {
		fmt.Println("  data:   not in archive — existing data directory left untouched")
	}

	// AI.md PART 21 requires a backup.restored audit event on every successful
	// restore; only the filename is recorded.
	if logMgr != nil {
		logMgr.WriteAuditEvent("", "backup.restored", "backup", "warn", "success", "", map[string]any{
			"filename": filepath.Base(backupFile),
		})
	}

	fmt.Println("Restore completed successfully")
}

// dirOrFileExists reports whether p exists on disk (any type).
func dirOrFileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// restoreReplaceDir atomically replaces dst with src without a window where dst
// is gone. The live dst is renamed aside first; only after the new content
// lands successfully is the old copy deleted. If the move fails, the live copy
// is rolled back so a partial restore never loses existing data (AI.md PART 21:
// keep existing valid data if a restore does not complete).
func restoreReplaceDir(src, dst string) error {
	oldDir := dst + ".restore-old"
	// Clear any stale backup from a previous interrupted restore.
	_ = os.RemoveAll(oldDir)

	haveOld := false
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, oldDir); err != nil {
			return fmt.Errorf("move existing %s aside: %w", dst, err)
		}
		haveOld = true
	}

	if err := restoreMoveDir(src, dst); err != nil {
		// Roll back: put the live copy back where it was.
		if haveOld {
			_ = os.RemoveAll(dst)
			if rbErr := os.Rename(oldDir, dst); rbErr != nil {
				return fmt.Errorf("restore %s failed (%v) and rollback failed: %w", dst, err, rbErr)
			}
		}
		return err
	}

	if haveOld {
		_ = os.RemoveAll(oldDir)
	}
	return nil
}

// restoreMoveDir moves src to dst using rename; falls back to a recursive copy
// when src and dst are on different filesystems (os.Rename returns an error).
func restoreMoveDir(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create parent of %s: %w", dst, err)
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	return restoreCopyDir(src, dst)
}

// restoreCopyDir recursively copies src into dst using stdlib only.
func restoreCopyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return restoreCopyFile(path, target, info.Mode())
	})
}

// restoreCopyFile copies a single file preserving its permission bits.
func restoreCopyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// randomPort generates a random port in the 64000-64999 range
// Per AI.md: default host port is random 64xxx
func randomPort() string {
	// Use crypto/rand for a seed, then pick a port in 64000-64999
	b := make([]byte, 2)
	if _, err := cryptorand.Read(b); err != nil {
		return "64000"
	}
	// combine both bytes (0-65535) before the modulus so the full
	// 0-999 offset is reachable; using only b[0] capped the range at 64255
	port := 64000 + (int(b[0])<<8|int(b[1]))%1000
	return strconv.Itoa(port)
}

// randomAvailablePort picks a random 64000-64999 port that is actually free.
// AI.md PART 12 requires the first-run port to be an unused port, so each
// candidate is probed with a real bind before it is accepted. After the
// attempt budget is exhausted the last candidate is returned so startup
// still surfaces a normal bind error rather than looping forever.
func randomAvailablePort() string {
	const attempts = 50
	candidate := randomPort()
	for i := 0; i < attempts; i++ {
		candidate = randomPort()
		ln, err := net.Listen("tcp", ":"+candidate)
		if err != nil {
			continue
		}
		ln.Close() //nolint:errcheck
		return candidate
	}
	return candidate
}

// parsePortSpec splits a port setting into its HTTP and HTTPS halves.
// AI.md PART 12 "Dual Port Support": a bare "8080" configures HTTP only,
// while "8090,8443" configures HTTP on 8090 and HTTPS on 8443.
func parsePortSpec(spec string) (string, string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}
	first, second, found := strings.Cut(spec, ",")
	first = strings.TrimSpace(first)
	if !found {
		return first, ""
	}
	return first, strings.TrimSpace(second)
}

// resolveServerPort returns the port setting from the highest-priority source
// that supplies one: the --port flag, then the PORT env var, then server.yml.
// An empty result means no port has ever been chosen and the caller must pick
// one (container default or a random unused port).
func resolveServerPort(flagPort string, cfg *config.AppConfig) string {
	if strings.TrimSpace(flagPort) != "" {
		return strings.TrimSpace(flagPort)
	}
	if envPort := strings.TrimSpace(os.Getenv("PORT")); envPort != "" {
		return envPort
	}
	if cfg != nil {
		return strings.TrimSpace(cfg.Server.Port)
	}
	return ""
}

// operatorRecipients returns the address operator notifications are delivered
// to. AI.md PART 17 routes every operator event to the `admin` contact role;
// sending them to the no-reply From address delivered them nowhere. The
// From address remains the last-resort fallback so a misconfigured admin
// contact never silently drops a critical alert.
func operatorRecipients(cfg *config.AppConfig) []string {
	if cfg == nil {
		return nil
	}
	if to := strings.TrimSpace(config.ResolveContactRole(cfg, "admin").Email); to != "" {
		return []string{to}
	}
	if from := strings.TrimSpace(cfg.Server.Notifications.Email.From.Email); from != "" {
		return []string{from}
	}
	return nil
}

// operatorLanguage returns the locale operator notification emails are
// rendered in: the configured default language, then the configured fallback,
// then the i18n default locale (AI.md PART 17, PART 30).
func operatorLanguage(cfg *config.AppConfig) string {
	if cfg != nil {
		if lang := strings.TrimSpace(cfg.Server.I18n.DefaultLanguage); lang != "" {
			return lang
		}
		if lang := strings.TrimSpace(cfg.Server.I18n.FallbackLanguage); lang != "" {
			return lang
		}
	}
	return "en"
}

// sendOperatorEmail dispatches a localized operator notification and reports
// whether it was delivered. A delivery failure is logged and never aborts the
// task that raised the notification.
func sendOperatorEmail(cfg *config.AppConfig, emailMgr *email.EmailManager, templateName string, vars map[string]string) bool {
	if emailMgr == nil {
		return false
	}
	if err := emailMgr.SendLocalizedTemplate(templateName, operatorLanguage(cfg), operatorRecipients(cfg), vars); err != nil {
		log.Printf("Warning: failed to send %s notification: %v", templateName, err)
		return false
	}
	return true
}

// readUpdateNotifiedVersion returns the version the update_available event was
// last raised for, or "" when no notification has been sent yet. A missing or
// unreadable file always reads as "" so a lost state file re-notifies rather
// than silently swallowing the alert.
func readUpdateNotifiedVersion(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// writeUpdateNotifiedVersion records the version the operator was told about so
// the next scheduled run does not repeat the same notification.
func writeUpdateNotifiedVersion(path, version string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		log.Printf("Warning: Failed to create update state directory: %v", err)
		return
	}
	if err := os.WriteFile(path, []byte(version+"\n"), 0o640); err != nil {
		log.Printf("Warning: Failed to record notified update version: %v", err)
	}
}

// criticalTaskEmails records scheduled tasks that already sent their own
// critical operator email for the execution that is about to fail. AI.md
// PART 17 suppresses scheduler_error when backup_failed or ssl_renewal_failed
// fires for the same execution, so the OnFailure hook consumes the marker
// instead of sending a second email.
var criticalTaskEmails sync.Map

// markCriticalTaskEmail flags taskID as having already notified the operator.
func markCriticalTaskEmail(taskID string) {
	criticalTaskEmails.Store(taskID, true)
}

// consumeCriticalTaskEmail reports whether taskID notified the operator during
// this execution and clears the marker so the next run starts clean.
func consumeCriticalTaskEmail(taskID string) bool {
	_, found := criticalTaskEmails.LoadAndDelete(taskID)
	return found
}

// listenAddress builds the bind address for net.Listen from the configured
// address and port. Wildcard addresses collapse to ":port" so a single
// listener accepts both IPv4 and IPv6 connections.
func listenAddress(address, port string) string {
	switch address {
	case "", "*", "::", "[::]", "0.0.0.0":
		return ":" + port
	}
	return net.JoinHostPort(address, port)
}

// generateOperatorToken generates a new operator token per AI.md PART 11.
// Format: tok_ prefix + 32 URL-safe random base62 chars.
func generateOperatorToken() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const tokenLen = 32
	b := make([]byte, tokenLen)
	if _, err := cryptorand.Read(b); err != nil {
		return "", fmt.Errorf("generating operator token: %w", err)
	}
	out := make([]byte, tokenLen)
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return "tok_" + string(out), nil
}

// generateEncryptionKey generates a new 32-byte AES-256-GCM at-rest encryption
// key per AI.md PART 11, base64-encoded for storage in server.security.encryption_key.
func generateEncryptionKey() (string, error) {
	const keyLen = 32
	b := make([]byte, keyLen)
	if _, err := cryptorand.Read(b); err != nil {
		return "", fmt.Errorf("generating encryption key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func handleUpdateCommand(cmd string, cfg *config.AppConfig) {
	args := flag.Args()
	branch := cfg.Server.Update.Branch
	if branch == "" {
		branch = cfg.Server.UpdateBranch
	}
	if branch == "" {
		branch = "stable"
	}

	ctx := context.Background()

	switch cmd {
	case "check":
		release, err := updater.CheckForUpdate(ctx, Version, branch, buildEpoch())
		if err != nil {
			fmt.Printf("Update check failed: %v\n", err)
			os.Exit(exGeneral)
		}
		fmt.Printf("Current version:  %s\n", Version)
		fmt.Printf("Update branch:    %s\n", branch)
		if release == nil {
			fmt.Println("Already up to date.")
			return
		}
		latestVersion := strings.TrimPrefix(release.TagName, "v")
		fmt.Printf("Latest version:   %s\n", latestVersion)
		fmt.Printf("Update available: %s\n", release.HTMLURL)
		fmt.Println("Run 'ipgaze --update yes' to install.")
	case "yes":
		release, err := updater.CheckForUpdate(ctx, Version, branch, buildEpoch())
		if err != nil {
			fmt.Printf("Update check failed: %v\n", err)
			os.Exit(exGeneral)
		}
		if release == nil {
			fmt.Println("Already up to date.")
			return
		}
		latestVersion := strings.TrimPrefix(release.TagName, "v")
		fmt.Printf("Updating from %s to %s...\n", Version, latestVersion)
		if err := updater.DoUpdate(ctx, release); err != nil {
			fmt.Printf("Update failed: %v\n", err)
			os.Exit(exGeneral)
		}
		fmt.Printf("Updated to %s successfully.\n", latestVersion)
		fmt.Println("Restarting...")
		if err := updater.RestartSelf(); err != nil {
			fmt.Printf("Restart failed: %v\nPlease restart the server manually.\n", err)
			os.Exit(0)
		}
	case "branch":
		if len(args) == 0 {
			fmt.Printf("Current branch: %s\n", branch)
			return
		}
		if args[0] != "stable" && args[0] != "beta" && args[0] != "daily" {
			fmt.Printf("Invalid branch: %s\n", args[0])
			fmt.Println("Valid branches: stable, beta, daily")
			os.Exit(exUsage)
		}
		cfg.Server.Update.Branch = args[0]
		cfg.Server.UpdateBranch = args[0]
		if err := config.SaveConfigToFile(); err != nil {
			log.Printf("Failed to save config: %v", err)
		}
		fmt.Printf("Branch set to: %s\n", args[0])
	default:
		fmt.Printf("Unknown update command: %s\n", cmd)
		fmt.Println("Available commands: check, yes, branch")
		os.Exit(exUsage)
	}
}

// torNoServerError is the exact message AI.md PART 31.1 mandates when a
// mutating tor subcommand cannot reach a running server.
const torNoServerError = "Error: no running server detected — start the server first"

// torControlTimeout bounds a control request. Restart, regenerate, and apply
// all wait on a Tor bootstrap, which routinely takes tens of seconds.
const torControlTimeout = 120 * time.Second

// torVanityData mirrors tor.VanityStatus as it appears on the wire.
type torVanityData struct {
	State          string   `json:"state"`
	Prefix         string   `json:"prefix"`
	Workers        int      `json:"workers"`
	Attempts       uint64   `json:"attempts"`
	Rate           float64  `json:"rate"`
	ElapsedSeconds float64  `json:"elapsed_seconds"`
	Candidates     []string `json:"candidates"`
	LastError      string   `json:"last_error"`
}

// torControlData is the union of every payload the /server/tor/* endpoints
// produce; each endpoint fills only the fields that apply to it.
type torControlData struct {
	Enabled     bool          `json:"enabled"`
	Running     bool          `json:"running"`
	Status      string        `json:"status"`
	Hostname    string        `json:"hostname"`
	BackendPort int           `json:"backend_port"`
	TorrcPath   string        `json:"torrc_path"`
	SiteDir     string        `json:"site_dir"`
	Valid       bool          `json:"valid"`
	Problem     string        `json:"problem"`
	Action      string        `json:"action"`
	Message     string        `json:"message"`
	Vanity      torVanityData `json:"vanity"`
}

// torControlEnvelope is the canonical API envelope of AI.md PART 14 as the
// Tor control endpoints return it.
type torControlEnvelope struct {
	OK      bool              `json:"ok"`
	Data    torControlData    `json:"data"`
	Error   string            `json:"error"`
	Message string            `json:"message"`
	Details map[string]string `json:"details"`
}

// failure renders the envelope's error for the terminal, preferring the
// specific reason the server put in details over the generic message.
func (e *torControlEnvelope) failure() string {
	if reason, ok := e.Details["reason"]; ok && reason != "" {
		return reason
	}
	if e.Message != "" {
		return e.Message
	}
	return e.Error
}

// torServerPort resolves the loopback port of the running server exactly as
// --status does: the configured bind port, defaulting to 8080.
func torServerPort(cfg *config.AppConfig) string {
	if cfg != nil && cfg.Server.Port != "" {
		return cfg.Server.Port
	}
	return "8080"
}

// torServerRunning reports whether a live server is reachable on loopback.
// Detection reuses the --status mechanism: the PID file the server wrote plus
// a health probe on the configured bind port. A dead PID file is a fast
// negative on a host, but containers deliberately write no PID file
// (AI.md PART 8), so the health probe is what ultimately decides.
func torServerRunning(pidFile, port string) bool {
	if running, _, err := paths.CheckPIDFile(pidFile); err == nil && !running && !paths.IsRunningInContainer() {
		return false
	}
	return checkHealth(port) == nil
}

// torControlCall issues one request to an internal /server/tor/* endpoint on
// loopback and decodes the canonical envelope. body may be nil for GET.
func torControlCall(port, method, endpoint string, body map[string]interface{}) (*torControlEnvelope, error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(encoded)
	}
	url := fmt.Sprintf("http://127.0.0.1:%s%s", port, endpoint)
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: torControlTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var env torControlEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("unexpected response from server (HTTP %d)", resp.StatusCode)
	}
	return &env, nil
}

// torControlRequire performs a control call for a subcommand that cannot work
// without a running server, exiting with the mandated message on failure.
func torControlRequire(port, method, endpoint string, body map[string]interface{}) *torControlEnvelope {
	env, err := torControlCall(port, method, endpoint, body)
	if err != nil {
		fmt.Fprintln(os.Stderr, torNoServerError)
		os.Exit(1)
	}
	if !env.OK {
		fmt.Fprintf(os.Stderr, "Error: %s\n", env.failure())
		os.Exit(exOsErr)
	}
	return env
}

// torRequireServer aborts with the mandated message when no server is running.
func torRequireServer(pidFile, port string) {
	if !torServerRunning(pidFile, port) {
		fmt.Fprintln(os.Stderr, torNoServerError)
		os.Exit(1)
	}
}

// printTorUsage prints the `ipgaze tor` help text.
func printTorUsage() {
	fmt.Println("Usage: ipgaze tor <subcommand>")
	fmt.Println("")
	fmt.Println("Tor is owned by the running server; these subcommands drive it")
	fmt.Println("through the server's loopback-only control channel.")
	fmt.Println("")
	fmt.Println("Subcommands:")
	fmt.Println("  status                        Show Tor hidden service status")
	fmt.Println("  validate                      Validate the Tor configuration")
	fmt.Println("  restart                       Restart the Tor hidden service")
	fmt.Println("  regenerate                    Regenerate the .onion address (destroys the current one)")
	fmt.Println("  vanity start <prefix> [-w N]  Search for an address starting with <prefix> (1-6 chars)")
	fmt.Println("  vanity stop                   Cancel the running vanity search")
	fmt.Println("  vanity apply [address]        Install a found vanity address (destroys the current one)")
	fmt.Println("  import-keys <path>            Import existing hidden service keys")
	fmt.Println("")
	fmt.Println("status and validate read on-disk state when no server is running;")
	fmt.Println("every other subcommand requires a running server.")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  ipgaze tor status")
	fmt.Println("  ipgaze tor vanity start news -w 4")
	fmt.Println("  ipgaze tor vanity stop")
	fmt.Println("  ipgaze tor vanity apply newsxyz")
	fmt.Println("  ipgaze tor import-keys /path/to/keys/")
}

// printTorVanityStatus renders the vanity search section of `tor status`.
// Per AI.md PART 31.1 the section appears whenever a search is running or a
// candidate is waiting on disk.
func printTorVanityStatus(v torVanityData) {
	running := v.State == "running"
	if !running && len(v.Candidates) == 0 && v.LastError == "" {
		return
	}
	fmt.Println("")
	fmt.Println("Vanity Search")
	fmt.Printf("  State:    %s\n", v.State)
	if running {
		fmt.Printf("  Prefix:   %s\n", v.Prefix)
		fmt.Printf("  Workers:  %d\n", v.Workers)
		fmt.Printf("  Attempts: %d\n", v.Attempts)
		fmt.Printf("  Rate:     %.2f/sec\n", v.Rate)
		fmt.Printf("  Elapsed:  %.0fs\n", v.ElapsedSeconds)
	}
	for _, addr := range v.Candidates {
		fmt.Printf("  Found:    %s\n", addr)
	}
	if v.LastError != "" {
		fmt.Printf("  Error:    %s\n", v.LastError)
	}
}

// torStatusFromDisk renders `tor status` from on-disk state, the read-only
// fallback AI.md PART 31.1 permits when no server is running.
func torStatusFromDisk(configDir, dataDir, logDir string) {
	fmt.Println("Tor Hidden Service")
	fmt.Println("  Status:   server not running")
	hostnameFile := filepath.Join(dataDir, "tor", "site", "hostname")
	if data, err := os.ReadFile(hostnameFile); err == nil {
		fmt.Printf("  Address:  %s\n", strings.TrimSpace(string(data)))
	} else {
		fmt.Println("  Address:  (not yet generated)")
	}
	fmt.Printf("  Config:   %s\n", filepath.Join(configDir, "tor", "torrc"))
	fmt.Printf("  Data:     %s\n", filepath.Join(dataDir, "tor"))
	fmt.Printf("  Log:      %s\n", filepath.Join(logDir, "tor.log"))
}

// torValidateFromDisk validates the on-disk Tor configuration without a
// running server, the second read-only fallback of AI.md PART 31.1.
func torValidateFromDisk(configDir, dataDir string, cfg *config.AppConfig) {
	mgr := tor.NewTorManager(tor.TorServiceConfig{
		ConfigDir: configDir,
		DataDir:   dataDir,
		Binary:    cfg.Server.Tor.Binary,
	})
	fmt.Println("Tor configuration (server not running)")
	fmt.Printf("  Config:   %s\n", mgr.TorrcPath())
	fmt.Printf("  Site:     %s\n", mgr.SiteDir())
	if err := mgr.Validate(); err != nil {
		fmt.Printf("  Result:   invalid — %v\n", err)
		os.Exit(exOsErr)
	}
	fmt.Println("  Result:   valid")
}

// torVanityStartArgs parses `vanity start <prefix> [-w N | --workers N]`.
func torVanityStartArgs(args []string) (string, int) {
	prefix := ""
	workers := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-w", "--workers":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --workers requires a value")
				os.Exit(exUsage)
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				fmt.Fprintf(os.Stderr, "Error: invalid worker count %q\n", args[i+1])
				os.Exit(exUsage)
			}
			workers = n
			i++
		default:
			if prefix != "" {
				fmt.Fprintf(os.Stderr, "Error: unexpected argument %q\n", args[i])
				os.Exit(exUsage)
			}
			prefix = args[i]
		}
	}
	if prefix == "" {
		fmt.Fprintln(os.Stderr, "Usage: ipgaze tor vanity start <prefix> [--workers N]")
		os.Exit(exUsage)
	}
	return prefix, workers
}

// torVanityCall performs a vanity control call, exiting 1 on any failure as
// AI.md PART 31.1 mandates for a busy search, an unresolvable candidate, or a
// post-apply hostname mismatch.
func torVanityCall(port, endpoint string, body map[string]interface{}) *torControlEnvelope {
	env, err := torControlCall(port, http.MethodPost, endpoint, body)
	if err != nil {
		fmt.Fprintln(os.Stderr, torNoServerError)
		os.Exit(1)
	}
	if !env.OK {
		fmt.Fprintf(os.Stderr, "Error: %s\n", env.failure())
		os.Exit(1)
	}
	return env
}

// handleTorVanityCommand dispatches `ipgaze tor vanity <start|stop|apply>`.
func handleTorVanityCommand(args []string, pidFile, port string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: ipgaze tor vanity <start|stop|apply>")
		os.Exit(exUsage)
	}
	switch args[0] {
	case "start":
		prefix, workers := torVanityStartArgs(args[1:])
		torRequireServer(pidFile, port)
		body := map[string]interface{}{"prefix": prefix}
		if workers > 0 {
			body["workers"] = workers
		}
		env := torVanityCall(port, "/server/tor/vanity/start", body)
		fmt.Printf("Vanity search started for prefix %q\n", prefix)
		fmt.Println("Check progress with: ipgaze tor status")
		if env.Data.Message != "" {
			fmt.Printf("  %s\n", env.Data.Message)
		}
	case "stop":
		torRequireServer(pidFile, port)
		env := torVanityCall(port, "/server/tor/vanity/stop", nil)
		if env.Data.Message != "" {
			fmt.Println(env.Data.Message)
		}
		fmt.Println("Candidates already written to disk are kept.")
	case "apply":
		address := ""
		if len(args) > 1 {
			address = args[1]
		}
		torRequireServer(pidFile, port)
		fmt.Println("WARNING: This will destroy the current .onion address and replace it with the vanity address.")
		fmt.Println("Any bookmarks or links to the current address will stop working.")
		fmt.Print("Type 'yes' to confirm: ")
		var confirm string
		fmt.Scanln(&confirm) //nolint:errcheck
		if confirm != "yes" {
			fmt.Println("Vanity apply cancelled.")
			return
		}
		env := torVanityCall(port, "/server/tor/vanity/apply",
			map[string]interface{}{"address": address})
		fmt.Println("Vanity address applied")
		fmt.Printf("  Address: %s\n", env.Data.Hostname)
		fmt.Printf("  Status:  %s\n", env.Data.Status)
	default:
		fmt.Fprintf(os.Stderr, "Unknown vanity subcommand: %s\n", args[0])
		os.Exit(exUsage)
	}
}

// handleTorCommand dispatches `ipgaze tor <subcommand>` per AI.md PART 31.1.
// The running server owns the embedded Tor process, so every subcommand is a
// request to the server's INTERNAL loopback control channel rather than a
// direct manipulation of Tor's files or process.
func handleTorCommand(args []string, configDir, dataDir, logDir, pidFile string, cfg *config.AppConfig) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		printTorUsage()
		return
	}

	sub := args[0]
	subArgs := args[1:]
	port := torServerPort(cfg)

	switch sub {
	case "status":
		if !torServerRunning(pidFile, port) {
			torStatusFromDisk(configDir, dataDir, logDir)
			return
		}
		env := torControlRequire(port, http.MethodGet, "/server/tor/status", nil)
		fmt.Println("Tor Hidden Service")
		fmt.Printf("  Status:   %s\n", env.Data.Status)
		if env.Data.Hostname != "" {
			fmt.Printf("  Address:  %s\n", env.Data.Hostname)
		} else {
			fmt.Println("  Address:  (not yet generated)")
		}
		if env.Data.BackendPort > 0 {
			fmt.Printf("  Backend:  127.0.0.1:%d\n", env.Data.BackendPort)
		}
		fmt.Printf("  Config:   %s\n", env.Data.TorrcPath)
		fmt.Printf("  Data:     %s\n", filepath.Join(dataDir, "tor"))
		fmt.Printf("  Log:      %s\n", filepath.Join(logDir, "tor.log"))
		printTorVanityStatus(env.Data.Vanity)

	case "validate":
		if !torServerRunning(pidFile, port) {
			torValidateFromDisk(configDir, dataDir, cfg)
			return
		}
		env := torControlRequire(port, http.MethodPost, "/server/tor/validate", nil)
		fmt.Println("Tor configuration")
		fmt.Printf("  Config:   %s\n", env.Data.TorrcPath)
		fmt.Printf("  Site:     %s\n", env.Data.SiteDir)
		if !env.Data.Valid {
			fmt.Printf("  Result:   invalid — %s\n", env.Data.Problem)
			os.Exit(exOsErr)
		}
		fmt.Println("  Result:   valid")

	case "restart":
		torRequireServer(pidFile, port)
		env := torControlRequire(port, http.MethodPost, "/server/tor/restart", nil)
		fmt.Println("Tor restarted successfully")
		fmt.Printf("  Status:   %s\n", env.Data.Status)
		if env.Data.Hostname != "" {
			fmt.Printf("  Address:  %s\n", env.Data.Hostname)
		}

	case "regenerate":
		torRequireServer(pidFile, port)
		fmt.Println("WARNING: This will destroy the current .onion address and generate a new one.")
		fmt.Println("Any bookmarks or links to the current address will stop working.")
		fmt.Print("Type 'yes' to confirm: ")
		var confirm string
		fmt.Scanln(&confirm) //nolint:errcheck
		if confirm != "yes" {
			fmt.Println("Regeneration cancelled.")
			return
		}
		env := torControlRequire(port, http.MethodPost, "/server/tor/regenerate", nil)
		fmt.Println("New .onion address generated")
		fmt.Printf("  Address:  %s\n", env.Data.Hostname)
		fmt.Printf("  Status:   %s\n", env.Data.Status)

	case "vanity":
		handleTorVanityCommand(subArgs, pidFile, port)

	case "import-keys":
		if len(subArgs) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: ipgaze tor import-keys <path>")
			os.Exit(exUsage)
		}
		srcDir, err := filepath.Abs(subArgs[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(exUsage)
		}
		torRequireServer(pidFile, port)
		env := torControlRequire(port, http.MethodPost, "/server/tor/import-keys",
			map[string]interface{}{"path": srcDir})
		fmt.Printf("Imported hidden service keys from %s\n", srcDir)
		fmt.Printf("  Address:  %s\n", env.Data.Hostname)
		fmt.Printf("  Status:   %s\n", env.Data.Status)

	default:
		fmt.Fprintf(os.Stderr, "Unknown tor subcommand: %s\n", sub)
		fmt.Fprintln(os.Stderr, "Run 'ipgaze tor help' for usage.")
		os.Exit(exUsage)
	}
}

// handleI2PCommand dispatches `ipgaze i2p <subcommand>` per AI.md PART 31.2.
// Subcommands: status, restart, regenerate
func handleI2PCommand(args []string, configDir, dataDir, logDir string, cfg *config.AppConfig) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		fmt.Println("Usage: ipgaze i2p <subcommand>")
		fmt.Println("")
		fmt.Println("Subcommands:")
		fmt.Println("  status              Show I2P eepsite status")
		fmt.Println("  restart             Restart the I2P eepsite")
		fmt.Println("  regenerate          Regenerate the .b32.i2p address (destroys current address)")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  ipgaze i2p status")
		fmt.Println("  ipgaze i2p regenerate")
		return
	}

	sub := args[0]

	mgr := i2p.NewI2PManager(i2p.I2PServiceConfig{
		ConfigDir:        configDir,
		DataDir:          dataDir,
		LogDir:           logDir,
		Enabled:          cfg.Server.I2P.Enabled,
		Binary:           cfg.Server.I2P.Binary,
		SAMAddress:       cfg.Server.I2P.SAMAddress,
		VirtualPort:      cfg.Server.I2P.VirtualPort,
		InboundLength:    cfg.Server.I2P.InboundLength,
		OutboundLength:   cfg.Server.I2P.OutboundLength,
		InboundQuantity:  cfg.Server.I2P.InboundQuantity,
		OutboundQuantity: cfg.Server.I2P.OutboundQuantity,
		SignatureType:    cfg.Server.I2P.SignatureType,
		BootstrapTimeout: cfg.Server.I2P.BootstrapTimeout,
	})

	switch sub {
	case "status":
		if !cfg.Server.I2P.Enabled {
			fmt.Println("I2P Eepsite: Disabled")
			return
		}
		if !mgr.IsAvailable() {
			fmt.Println("I2P Eepsite: No Provider (no i2pd binary or reachable SAM bridge)")
			return
		}
		info := mgr.GetInfo()
		fmt.Printf("I2P Eepsite: %s (%s)\n", info.Status, info.Provider)
		if info.Hostname != "" {
			fmt.Printf("  Address:  %s\n", info.Hostname)
		} else {
			fmt.Println("  Address:  (not yet generated)")
		}
		fmt.Printf("  Config:   %s\n", filepath.Join(configDir, "i2p"))
		fmt.Printf("  Data:     %s\n", filepath.Join(dataDir, "i2p"))

	case "restart":
		if !mgr.IsAvailable() {
			fmt.Fprintln(os.Stderr, "no I2P provider found — cannot restart")
			os.Exit(exOsErr)
		}
		fmt.Println("Stopping I2P eepsite...")
		_ = mgr.Stop()
		fmt.Println("Starting I2P eepsite...")
		if err := mgr.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start I2P eepsite: %v\n", err)
			os.Exit(exOsErr)
		}
		fmt.Println("I2P eepsite restarted successfully")
		fmt.Printf("  Address: %s\n", mgr.GetHostname())

	case "regenerate":
		if !mgr.IsAvailable() {
			fmt.Fprintln(os.Stderr, "no I2P provider found — cannot regenerate")
			os.Exit(exOsErr)
		}
		fmt.Println("WARNING: This will destroy the current .b32.i2p address and generate a new one.")
		fmt.Println("Any bookmarks or links to the current address will stop working.")
		fmt.Print("Type 'yes' to confirm: ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "yes" {
			fmt.Println("Regeneration cancelled.")
			return
		}
		hostname, err := mgr.RegenerateAddress()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to regenerate address: %v\n", err)
			os.Exit(exIoErr)
		}
		fmt.Println("New I2P eepsite address generated.")
		fmt.Printf("  Address: %s\n", hostname)

	default:
		fmt.Fprintf(os.Stderr, "Unknown i2p subcommand: %s\n", sub)
		fmt.Fprintln(os.Stderr, "Run 'ipgaze i2p help' for usage.")
		os.Exit(exUsage)
	}
}
