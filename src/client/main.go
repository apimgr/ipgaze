package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/apimgr/ipgaze/src/client/api"
	cliout "github.com/apimgr/ipgaze/src/client/cli"
	paths "github.com/apimgr/ipgaze/src/client/path"
	"github.com/apimgr/ipgaze/src/client/setup"
	"github.com/apimgr/ipgaze/src/client/updater"
	"github.com/apimgr/ipgaze/src/common/display"
	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/config"
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

// Project constants (hardcoded per AI.md PART 32).
const (
	projectName = "ipgaze"
	projectOrg  = "apimgr"
)

// Exit codes (AI.md PART 32 "Exit Codes" table).
const (
	// exitSuccess signals a completed operation.
	exitSuccess = 0
	// exitGeneral is any failure with no more specific code.
	exitGeneral = 1
	// exitConfig is a configuration error (missing or invalid settings).
	exitConfig = 2
	// exitConnection is a transport failure reaching the server.
	exitConnection = 3
	// exitAuth is an authentication or authorization failure.
	exitAuth = 4
	// exitNotFound is a missing resource.
	exitNotFound = 5
	// exitUsage is a bad command line (sysexits EX_USAGE).
	exitUsage = 64
)

// supportedShells lists every shell the completion and init generators handle.
const supportedShells = "bash, zsh, fish, sh, dash, ksh, powershell, pwsh"

// truthyFlag is a boolean command-line flag whose value is decoded with
// config.ParseBool, so locale forms (yes/no, oui/non, si/no, da/net) are
// accepted alongside true/false (AI.md PART 32: "ALL boolean inputs MUST use
// config.ParseBool() or config.IsTruthy()").
type truthyFlag struct {
	set   bool
	value bool
	raw   string
}

// String renders the raw text the user supplied.
func (f *truthyFlag) String() string {
	if f == nil || f.raw == "" {
		return "false"
	}
	return f.raw
}

// Set decodes the flag value through config.ParseBool.
func (f *truthyFlag) Set(s string) error {
	v, err := config.ParseBool(s, true)
	if err != nil {
		return err
	}
	f.raw = s
	f.value = v
	f.set = true
	return nil
}

// IsBoolFlag lets the flag package accept the bare form (--debug) as well as
// an explicit value (--debug=yes).
func (f *truthyFlag) IsBoolFlag() bool { return true }

// Bool reports the decoded value.
func (f *truthyFlag) Bool() bool { return f != nil && f.value }

// envOr returns value when non-empty, otherwise the named environment
// variable. It implements the flag > env > config tier order of AI.md PART 32.
func envOr(value, envName string) string {
	if value != "" {
		return value
	}
	return os.Getenv(envName)
}

// stdinIsTerminal reports whether stdin is an interactive terminal.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// exitCodeForError maps an API error to the PART 32 exit-code taxonomy.
func exitCodeForError(err error) int {
	switch {
	case errors.Is(err, api.ErrTokenRevoked):
		return exitAuth
	case api.IsConnectionError(err):
		return exitConnection
	case api.IsUnauthorized(err):
		return exitAuth
	case api.IsNotFound(err):
		return exitNotFound
	}
	return exitGeneral
}

func main() {
	// Create all required client directories on startup.
	if err := ensureDirectories(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not create client directories: %v\n", err)
	}

	// Get actual binary name for display.
	binaryName := filepath.Base(os.Args[0])

	// lang is resolved after flag.Parse; flag.Usage reads it at call time.
	lang := ""

	// Define flags.
	var (
		showHelp      truthyFlag
		showVersion   truthyFlag
		debugFlag     truthyFlag
		serverURL     string
		outputFlag    string
		field         string
		langFlag      string
		colorFlag     string
		shellCmd      string
		tokenFlag     string
		tokenFileFlag string
		configFlag    string
		updateCmd     string
	)

	flag.Var(&showHelp, "h", tr(&lang, "client.help_flag"))
	flag.Var(&showHelp, "help", tr(&lang, "client.help_flag"))
	flag.Var(&showVersion, "v", tr(&lang, "client.version_flag"))
	flag.Var(&showVersion, "version", tr(&lang, "client.version_flag"))
	flag.Var(&debugFlag, "debug", tr(&lang, "client.debug_flag"))
	flag.StringVar(&serverURL, "server", "", tr(&lang, "client.server_flag"))
	flag.StringVar(&outputFlag, "output", "", tr(&lang, "client.output_flag"))
	flag.StringVar(&field, "field", "", tr(&lang, "client.field_flag"))
	flag.StringVar(&langFlag, "lang", "", tr(&lang, "client.lang_flag"))
	flag.StringVar(&colorFlag, "color", "", tr(&lang, "client.color_flag"))
	flag.StringVar(&shellCmd, "shell", "", tr(&lang, "client.shell_flag"))
	flag.StringVar(&tokenFlag, "token", "", tr(&lang, "client.token_flag"))
	flag.StringVar(&tokenFileFlag, "token-file", "", tr(&lang, "client.token_file_flag"))
	flag.StringVar(&configFlag, "config", "", tr(&lang, "client.config_flag"))
	flag.StringVar(&updateCmd, "update", "", tr(&lang, "client.update_flag"))

	flag.Usage = func() {
		printUsage(os.Stderr, binaryName, lang)
	}

	flag.Parse()

	// Capture the raw --server/--token flag values before the priority
	// fallback chain below overwrites serverURL with env/config/default
	// values — persistCLIFlags needs to know specifically whether the FLAG
	// (not env or config) was used, since only the flag triggers a cli.yml
	// save (AI.md PART 32).
	flagServerURL := serverURL

	// Resolve the config file the whole run reads and writes (--config NAME,
	// --config /abs/path.yml, or the platform default).
	configPath, err := paths.ResolveConfigPath(configFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_config_path", "error", err.Error()))
		os.Exit(exitConfig)
	}

	// Auto-create cli.yml with commented defaults on first run (AI.md PART 32).
	if _, ensureErr := setup.EnsureConfigFile(configPath); ensureErr != nil {
		fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.warn_create_config", "error", ensureErr.Error()))
	}

	cfg, cfgErr := loadConfig(configPath)
	if cfgErr != nil {
		cfg = &setup.CLIConfig{}
	}

	// Resolve output language: --lang flag > defaults.lang > environment.
	langFlag = stringOrDefault(langFlag, configLangDefault(cfg))
	lang = getLanguage(langFlag)

	// Debug: --debug flag > IPGAZE_DEBUG env > cli.yml debug.
	debug := cfg.DebugEnabled()
	if raw := os.Getenv("IPGAZE_DEBUG"); raw != "" {
		debug = config.IsTruthy(raw)
	}
	if debugFlag.set {
		debug = debugFlag.Bool()
	}

	logger := newClientLogger(cfg, debug)

	// Color: --color flag > output.color.
	colorFlag = stringOrDefault(colorFlag, cfg.OutputColor())
	out := cliout.NewOutput(colorFlag)

	// Output format: --output flag > IPGAZE_OUTPUT_FORMAT env > output.format.
	outputFormat := envOr(outputFlag, "IPGAZE_OUTPUT_FORMAT")
	outputFormat = stringOrDefault(outputFormat, cfg.OutputFormat())
	if !setup.IsValidOutputFormat(outputFormat) {
		fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_invalid_output",
			"format", outputFormat, "formats", strings.Join(setup.OutputFormats, ", ")))
		os.Exit(exitUsage)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "debug: config=%s server=%s args=%v\n", configPath, serverURL, flag.Args())
	}
	logger.Debug("start config=%s output=%s args=%v", configPath, outputFormat, flag.Args())

	// Handle --shell completions/init/help.
	// Pass flag.Args() so an explicit SHELL arg (e.g. --shell completions bash) is respected.
	if shellCmd != "" {
		os.Exit(handleClientShellCommand(shellCmd, binaryName, lang, flag.Args()))
	}

	// Handle help (exits immediately, never TUI).
	if showHelp.Bool() {
		printUsage(os.Stdout, binaryName, lang)
		os.Exit(exitSuccess)
	}

	// Server URL priority: flag > env > config > compiled default (AI.md PART 32).
	serverURL = envOr(serverURL, "IPGAZE_SERVER_PRIMARY")
	serverURL = stringOrDefault(serverURL, cfg.Server.Primary)
	serverURL = stringOrDefault(serverURL, cfg.Defaults.Server)
	serverURL = stringOrDefault(serverURL, OfficialSite)

	// --version prints without needing a server; the extended block is added
	// only when one is configured and reachable (AI.md PART 32).
	if showVersion.Bool() {
		printVersion(serverURL, lang)
		os.Exit(exitSuccess)
	}

	if serverURL == "" {
		fmt.Fprintf(os.Stderr, "%s\n", tr(&lang, "client.err_no_server"))
		os.Exit(exitConfig)
	}

	// API token resolution per AI.md PART 32:
	// --token > --token-file > IPGAZE_TOKEN > auth.token > auth.token_file.
	token := resolveToken(tokenFlag, tokenFileFlag, cfg)

	// Persist --server/--token to cli.yml, but only if the flag was passed
	// and the existing stored value is empty or invalid (AI.md PART 32:
	// "save to cli.yml only if empty/invalid"; never overwrites an
	// already-valid stored value). Env vars and defaults never persist.
	persistCLIFlags(cfg, flagServerURL, tokenFlag, configPath)

	// Build API client.
	userAgent := fmt.Sprintf("%s-cli/%s", projectName, Version)
	client := api.NewAPIClient(serverURL, token, userAgent, lang)
	client.SetTimeout(resolveTimeout(cfg))
	ctx := context.Background()

	// Handle --update (check or install) — runs before the version-gate check.
	if updateCmd != "" {
		os.Exit(handleUpdate(ctx, client, cfg, updateCmd, lang))
	}

	// cli_min_version enforcement plus the update.auto decision on every start
	// (AI.md PART 32 step 1/2). Skipped for unversioned development builds.
	if Version != "devel" {
		enforceVersionPolicy(ctx, client, cfg, lang)
	}

	// Determine display mode per AI.md PART 32 auto-detection rules,
	// honoring the cli.yml display.mode override when set.
	args := flag.Args()
	mode := detectMode(os.Args, cfg.Display.Mode)
	if !cfg.TUIEnabled() && mode == "tui" {
		mode = "cli"
	}

	if mode == "tui" {
		// Interactive terminal + no command → TUI mode.
		runTUI(ctx, client, out, cfg)
		return
	}

	os.Exit(runCLI(ctx, client, out, args, outputFormat, field, lang))
}

// stringOrDefault returns value when non-empty, otherwise def.
func stringOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

// configLangDefault returns the defaults.lang setting, treating "auto" as unset
// so the environment chain still applies.
func configLangDefault(cfg *setup.CLIConfig) string {
	l := cfg.DefaultLang()
	if l == "auto" {
		return ""
	}
	return l
}

// resolveTimeout returns the HTTP timeout: IPGAZE_SERVER_TIMEOUT env overrides
// the server.timeout config value (AI.md PART 32 environment variable table).
func resolveTimeout(cfg *setup.CLIConfig) time.Duration {
	if raw := os.Getenv("IPGAZE_SERVER_TIMEOUT"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return cfg.RequestTimeout()
}

// tr translates key in the language lang currently points at. The pointer
// indirection lets the flag descriptions, built before flag.Parse runs, pick up
// the resolved language when they are finally rendered.
func tr(lang *string, key string) string {
	locale := "en"
	if lang != nil && *lang != "" {
		locale = *lang
	}
	return i18n.Translate(locale, key)
}

// trf translates key and substitutes {name} placeholders from key/value pairs.
func trf(lang, key string, args ...string) string {
	if lang == "" {
		lang = "en"
	}
	return i18n.TranslateFormat(lang, key, args...)
}

// printUsage writes the translated help screen.
func printUsage(w *os.File, binaryName, lang string) {
	fmt.Fprintf(w, "%s\n\n", trf(lang, "client.usage_line", "binary", binaryName))
	fmt.Fprintf(w, "%s\n\n", trf(lang, "client.description"))
	fmt.Fprintf(w, "%s\n", trf(lang, "client.options_header"))

	options := [][2]string{
		{"-h, --help", "client.help_flag"},
		{"-v, --version", "client.version_flag"},
		{"--config NAME", "client.config_flag"},
		{"--server URL", "client.server_flag"},
		{"--token TOKEN", "client.token_flag"},
		{"--token-file FILE", "client.token_file_flag"},
		{"--output FORMAT", "client.output_flag"},
		{"--field NAME", "client.field_flag"},
		{"--lang CODE", "client.lang_flag"},
		{"--color MODE", "client.color_flag"},
		{"--debug", "client.debug_flag"},
		{"--shell CMD", "client.shell_flag"},
		{"--update CMD", "client.update_flag"},
	}
	for _, opt := range options {
		fmt.Fprintf(w, "  %-20s %s\n", opt[0], trf(lang, opt[1]))
	}

	fmt.Fprintf(w, "\n%s\n", trf(lang, "client.formats_header",
		"formats", strings.Join(setup.OutputFormats, ", ")))
	fmt.Fprintf(w, "%s\n", trf(lang, "client.fields_header",
		"fields", strings.Join(api.FieldNames, ", ")))
	fmt.Fprintf(w, "%s\n", trf(lang, "client.shells_header", "shells", supportedShells))

	fmt.Fprintf(w, "\n%s\n", trf(lang, "client.examples_header"))
	examples := [][2]string{
		{binaryName, "client.example_own_ip"},
		{binaryName + " 8.8.8.8", "client.example_lookup_ip"},
		{binaryName + " --output json", "client.example_json"},
		{binaryName + " --field country 8.8.8.8", "client.example_field"},
		{binaryName + " --server https://ifcfg.us", "client.example_server"},
		{binaryName + " --config work", "client.example_config"},
		{binaryName + " --update check", "client.example_update_check"},
		{binaryName + " --update yes", "client.example_update_install"},
	}
	for _, ex := range examples {
		fmt.Fprintf(w, "  %-34s # %s\n", ex[0], trf(lang, ex[1]))
	}
}

// printVersion writes the PART 32 version line plus, when the server answers,
// the extended server and build-info block.
func printVersion(serverURL, lang string) {
	fmt.Printf("%s-cli %s (%s) built %s\n", projectName, Version, CommitID, BuildDate)

	if serverURL == "" {
		return
	}

	userAgent := fmt.Sprintf("%s-cli/%s", projectName, Version)
	client := api.NewAPIClient(serverURL, "", userAgent, lang)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.Autodiscover(ctx)
	if err != nil {
		return
	}

	fmt.Println()
	fmt.Printf("%s: %s\n", trf(lang, "client.version_server_label"), serverURL)
	fmt.Printf("%s: %s\n", trf(lang, "client.version_server_version_label"), info.Version)
	fmt.Println()
	fmt.Printf("%s:\n", trf(lang, "client.version_build_info_label"))
	fmt.Printf("  Go: %s\n", runtime.Version())
	fmt.Printf("  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

// handleUpdate runs --update check or --update yes and returns the exit code.
func handleUpdate(ctx context.Context, client *api.APIClient, cfg *setup.CLIConfig, cmd, lang string) int {
	switch cmd {
	case "check":
		result, err := updater.CheckForUpdates(ctx, client, Version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_update_check", "error", err.Error()))
			return exitCodeForError(err)
		}
		if result.BelowMin {
			fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_cli_too_old",
				"version", result.MinVersion, "binary", filepath.Base(os.Args[0])))
		}
		if !result.NeedsUpdate() {
			fmt.Println(trf(lang, "client.update_up_to_date"))
			return exitSuccess
		}
		fmt.Println(trf(lang, "client.update_available",
			"current", result.Current, "available", result.Available))
		return offerUpdate(ctx, client, cfg, result, lang)

	case "yes", "":
		if err := updater.Do(ctx, client, projectName, "", Version); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_update_failed", "error", err.Error()))
			return exitCodeForError(err)
		}
		return exitSuccess

	default:
		fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_unknown_update", "command", cmd))
		return exitUsage
	}
}

// offerUpdate applies the PART 32 step-2 decision: auto-update silently when
// update.auto is truthy and the session is non-interactive, otherwise prompt.
func offerUpdate(ctx context.Context, client *api.APIClient, cfg *setup.CLIConfig, result *updater.CheckResult, lang string) int {
	if !result.NeedsUpdate() {
		return exitSuccess
	}

	interactive := stdinIsTerminal()

	if cfg.UpdateAuto() && !interactive {
		return runUpdate(ctx, client, lang)
	}

	if !interactive {
		return exitSuccess
	}

	fmt.Print(trf(lang, "client.update_prompt") + " ")
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || !config.IsTruthy(strings.TrimSpace(answer)) {
		return exitSuccess
	}
	return runUpdate(ctx, client, lang)
}

// runUpdate performs the download-and-replace update and reports the exit code.
func runUpdate(ctx context.Context, client *api.APIClient, lang string) int {
	if err := updater.Do(ctx, client, projectName, "", Version); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_update_failed", "error", err.Error()))
		return exitCodeForError(err)
	}
	return exitSuccess
}

// enforceVersionPolicy refuses to continue when the CLI is below the server's
// cli_min_version, and otherwise applies the update.auto decision.
func enforceVersionPolicy(ctx context.Context, client *api.APIClient, cfg *setup.CLIConfig, lang string) {
	result, err := updater.CheckForUpdates(ctx, client, Version)
	if err != nil {
		// Non-fatal: autodiscover unreachable, continue with the request.
		return
	}
	if result.BelowMin {
		fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_cli_too_old",
			"version", result.MinVersion, "binary", filepath.Base(os.Args[0])))
		os.Exit(exitGeneral)
	}
	if result.NeedsUpdate() && cfg.UpdateAuto() && !stdinIsTerminal() {
		runUpdate(ctx, client, lang)
	}
}

// runCLI handles command-line (non-TUI) output and returns the process exit code.
func runCLI(ctx context.Context, client *api.APIClient, out *cliout.Output, args []string, outputFormat, field, lang string) int {
	if field != "" {
		var (
			value string
			err   error
		)
		if len(args) > 0 {
			value, err = client.GetIPField(ctx, args[0], field)
		} else {
			value, err = client.GetField(ctx, field)
		}
		if errors.Is(err, api.ErrTokenRevoked) {
			handleTokenRevoked(lang)
		}
		if err != nil {
			out.PrintError("%v", err)
			return exitCodeForError(err)
		}
		fmt.Println(value)
		return exitSuccess
	}

	var (
		ipResp *api.IPResponse
		err    error
	)
	if len(args) > 0 {
		ipResp, err = client.GetIPJSON(ctx, args[0])
	} else {
		ipResp, err = client.GetMyIPJSON(ctx)
	}
	if errors.Is(err, api.ErrTokenRevoked) {
		handleTokenRevoked(lang)
	}
	if err != nil {
		out.PrintError("%v", err)
		return exitCodeForError(err)
	}

	if renderErr := renderRecord(os.Stdout, outputFormat, ipResp); renderErr != nil {
		out.PrintError("%v", renderErr)
		return exitGeneral
	}
	return exitSuccess
}

// detectMode returns "tui", "cli", or "plain" based on environment and args (AI.md PART 32).
// TUI auto-detection uses display.DetectDisplayEnv() per AI.md PART 32.
// override is the cli.yml display.mode value ("auto"/"gui"/"tui"); a non-auto
// value forces the interactive display mode instead of auto-detecting it. This
// project ships no native GUI, so "gui" resolves to the TUI path (the same
// collapse the auto path already applies to a detected GUI environment).
func detectMode(args []string, override string) string {
	// Exit-immediately flags — never TUI.
	for _, arg := range args[1:] {
		switch arg {
		case "-h", "--help", "-v", "--version":
			return "cli"
		}
	}

	forceInteractive := override == "gui" || override == "tui"

	// Use display.DetectDisplayEnv() for TUI auto-detection per AI.md PART 32.
	denv := display.DetectDisplayEnv()

	// Headless or plain CLI environment → plain output, unless the operator
	// explicitly forced an interactive mode via cli.yml display.mode.
	if !forceInteractive && denv.IsAutoDetectDisplayModeHeadless() {
		return "plain"
	}

	// Config-only flags do not prevent TUI.
	configFlags := map[string]bool{
		"--config": true, "--server": true, "--token": true, "--debug": true,
	}

	// valueFlags take a separate argument in the space form (--server URL);
	// that value must be skipped so it is not mistaken for a positional
	// argument (AI.md PART 32 TUI-detection loop).
	valueFlags := map[string]bool{
		"--config": true, "--server": true, "--token": true,
	}

	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		if !strings.HasPrefix(arg, "-") {
			// Positional argument / command → CLI mode.
			return "cli"
		}
		name := strings.Split(arg, "=")[0]
		if !configFlags[name] {
			// Action flag → CLI mode.
			return "cli"
		}
		if valueFlags[name] && !strings.Contains(arg, "=") {
			i++
		}
	}

	// Forced interactive mode wins over auto-detection once no command was given.
	if forceInteractive {
		return "tui"
	}

	// No args or config-only flags → TUI when terminal supports it, else plain.
	if denv.IsAutoDetectDisplayModeTUI() || denv.IsAutoDetectDisplayModeGUI() {
		return "tui"
	}
	return "plain"
}

// readTokenFile reads a token from a file after verifying its permissions.
func readTokenFile(path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	if err := checkFilePermissions(path); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// resolveToken returns the API token following the PART 32 priority chain:
// --token > --token-file > IPGAZE_TOKEN > auth.token > auth.token_file.
func resolveToken(tokenFlag, tokenFileFlag string, cfg *setup.CLIConfig) string {
	if tokenFlag != "" {
		return tokenFlag
	}
	if t := readTokenFile(tokenFileFlag); t != "" {
		return t
	}
	if t := os.Getenv("IPGAZE_TOKEN"); t != "" {
		return t
	}
	if cfg == nil {
		return ""
	}
	if cfg.Auth.Token != "" {
		return cfg.Auth.Token
	}
	return readTokenFile(cfg.Auth.TokenFile)
}

// persistCLIFlags saves --server/--token to cli.yml when the flag was
// passed and the corresponding stored value is empty or invalid (AI.md
// PART 32 "Server Address Resolution" / "Authentication": both flags "save
// to cli.yml only if config value is empty/invalid"). An already-valid
// stored value is never overwritten, and env vars / compiled defaults never
// persist — only an explicit flag does.
func persistCLIFlags(cfg *setup.CLIConfig, flagServer, flagToken, configPath string) {
	if cfg == nil {
		return
	}
	changed := false
	if flagServer != "" && setup.ValidateServerURL(flagServer) && !setup.ValidateServerURL(cfg.Server.Primary) {
		cfg.Server.Primary = setup.SaveIfEmptyOrInvalid(cfg.Server.Primary, flagServer, setup.ValidateServerURL)
		changed = true
	}
	if flagToken != "" && setup.ValidateToken(flagToken) && !setup.ValidateToken(cfg.Auth.Token) {
		cfg.Auth.Token = setup.SaveIfEmptyOrInvalid(cfg.Auth.Token, flagToken, setup.ValidateToken)
		changed = true
	}
	if !changed {
		return
	}
	if err := setup.SaveCLIConfigToFile(cfg, configPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to save cli.yml: %v\n", err)
	}
}

// handleTokenRevoked logs the cli.token_revoked_detected audit event, removes the
// cached token from disk, and exits. Called whenever doAPIRequest returns ErrTokenRevoked.
// (AI.md PART 32 audit events table)
func handleTokenRevoked(lang string) {
	fmt.Fprintln(os.Stderr, "audit: cli.token_revoked_detected")
	fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_token_revoked"))
	// Clear the token field in cli.yml by rewriting config without a token.
	configPath := paths.ConfigFile()
	if data, err := os.ReadFile(configPath); err == nil {
		var lines []string
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "token:") {
				lines = append(lines, line)
			}
		}
		// 0o600: cli.yml may contain other secrets besides the token being
		// cleared here (e.g. server URL credentials); permissions_unix.go's
		// checkFilePermissions() rejects any mode with group/other bits set,
		// so writing 0o644 here would make the client refuse its own
		// rewritten config on the very next load.
		_ = os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0o600)
	}
	os.Exit(exitAuth)
}

// loadConfig loads the CLI config from the resolved config path.
// Validates file permissions before reading.
func loadConfig(configPath string) (*setup.CLIConfig, error) {
	if err := checkFilePermissions(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		return nil, fmt.Errorf("insecure config file permissions")
	}
	return setup.LoadCLIConfigFrom(configPath)
}

// handleClientShellCommand handles --shell completions/init/help for ipgaze-cli
// and returns the process exit code. args is the list of remaining positional
// arguments from flag.Args(); the first element, if present, is the explicit
// shell name (e.g. "bash"). When absent, the shell is auto-detected from the
// $SHELL environment variable per AI.md PART 32.
func handleClientShellCommand(cmd, binaryName, lang string, args []string) int {
	// Determine target shell: explicit first arg, then auto-detect from $SHELL.
	shell := ""
	if len(args) > 0 {
		shell = strings.ToLower(args[0])
	}
	if shell == "" {
		shell = filepath.Base(os.Getenv("SHELL"))
	}
	if shell == "" {
		shell = "bash"
	}

	switch cmd {
	case "completions":
		return printClientCompletions(shell, binaryName, lang)
	case "init":
		return printClientInit(shell, binaryName, lang)
	case "help", "--help":
		fmt.Println(trf(lang, "client.shell_help_usage", "binary", binaryName))
		fmt.Println(trf(lang, "client.shells_header", "shells", supportedShells))
		return exitSuccess
	default:
		fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_unknown_shell_command", "command", cmd))
		return exitUsage
	}
}

// completionFlags is the flag list every completion generator offers.
const completionFlags = "--help --version --config --server --token --token-file " +
	"--output --field --lang --color --debug --shell --update"

// printClientCompletions outputs the completion script for the requested shell
// and returns the process exit code.
func printClientCompletions(shell, binaryName, lang string) int {
	formats := strings.Join(setup.OutputFormats, " ")
	fields := strings.Join(api.FieldNames, " ")

	switch shell {
	case "bash":
		fmt.Printf(`# %s bash completions
_%s_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="%s"
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
}
complete -F _%s_completions %s
`, binaryName, binaryName, completionFlags, binaryName, binaryName)
	case "zsh":
		fmt.Printf(`#compdef %s
_arguments \
    '-h[Show help]' '--help[Show help]' \
    '-v[Show version]' '--version[Show version]' \
    '--config[Config file name or path]:name:' \
    '--server[Server URL]:URL:' \
    '--token[API token]:token:' \
    '--token-file[File containing the API token]:file:_files' \
    '--output[Output format]:format:(%s)' \
    '--field[Output specific field]:field:(%s)' \
    '--lang[Language]:lang:(en es fr de zh ar ja)' \
    '--color[Color output]:mode:(auto yes no)' \
    '--debug[Enable debug output]' \
    '--shell[Shell integration]:cmd:(completions init help)' \
    '--update[Auto-update]:cmd:(check yes)'
`, binaryName, formats, fields)
	case "fish":
		fmt.Printf(`complete -c %s -s h -l help -d 'Show help'
complete -c %s -s v -l version -d 'Show version'
complete -c %s -l config -d 'Config file name or path' -r
complete -c %s -l server -d 'Server URL' -r
complete -c %s -l token -d 'API token' -r
complete -c %s -l token-file -d 'File containing the API token' -r -F
complete -c %s -l output -d 'Output format' -r -a '%s'
complete -c %s -l field -d 'Output specific field' -r -a '%s'
complete -c %s -l lang -d 'Language' -r -a 'en es fr de zh ar ja'
complete -c %s -l color -d 'Color output' -r -a 'auto yes no'
complete -c %s -l debug -d 'Enable debug output'
complete -c %s -l shell -d 'Shell integration' -r -a 'completions init help'
complete -c %s -l update -d 'Auto-update' -r -a 'check yes'
`, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName,
			binaryName, formats, binaryName, fields, binaryName, binaryName,
			binaryName, binaryName, binaryName)
	case "sh", "dash":
		// POSIX sh/dash basic completions using bash builtins when available.
		fmt.Printf(`# %s sh/dash completions (uses bash builtins if available)
if command -v complete >/dev/null 2>&1 && command -v compgen >/dev/null 2>&1; then
_%s_completions() {
    local opts="%s"
    COMPREPLY=( $(compgen -W "$opts" -- "${COMP_WORDS[COMP_CWORD]}") )
}
complete -F _%s_completions %s
fi
`, binaryName, binaryName, completionFlags, binaryName, binaryName)
	case "ksh":
		// ksh93 programmable completions.
		fmt.Printf(`# %s ksh completions
function _%s_complete {
    typeset opts="%s"
    set -A REPLY -- $(print -- $opts | tr ' ' '\n' | grep "^${2}")
}
complete -F _%s_complete %s
`, binaryName, binaryName, completionFlags, binaryName, binaryName)
	case "powershell", "pwsh":
		// PowerShell/pwsh Register-ArgumentCompleter.
		fmt.Printf(`# %s PowerShell completions
Register-ArgumentCompleter -Native -CommandName '%s' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $options = '%s' -split ' '
    $options | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new(
            $_, $_, 'ParameterValue', $_
        )
    }
}
`, binaryName, binaryName, completionFlags)
	default:
		fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_unsupported_shell",
			"shell", shell, "shells", supportedShells))
		return exitUsage
	}
	return exitSuccess
}

// printClientInit outputs the shell rc snippet that loads completions at shell
// startup and returns the process exit code.
func printClientInit(shell, binaryName, lang string) int {
	switch shell {
	case "bash":
		fmt.Printf("source <(%s --shell completions bash)\n", binaryName)
	case "zsh":
		fmt.Printf("source <(%s --shell completions zsh)\n", binaryName)
	case "fish":
		fmt.Printf("%s --shell completions fish | source\n", binaryName)
	case "sh", "dash":
		fmt.Printf("eval \"$(%s --shell completions %s)\"\n", binaryName, shell)
	case "ksh":
		fmt.Printf("eval \"$(%s --shell completions ksh)\"\n", binaryName)
	case "powershell", "pwsh":
		fmt.Printf("Invoke-Expression (& '%s' --shell completions powershell)\n", binaryName)
	default:
		fmt.Fprintf(os.Stderr, "%s\n", trf(lang, "client.err_unsupported_shell",
			"shell", shell, "shells", supportedShells))
		return exitUsage
	}
	return exitSuccess
}

// getLanguage resolves the output language using the priority chain from AI.md PART 30:
// 1. --lang flag  2. LC_ALL env  3. LANG env  4. default "en"
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
