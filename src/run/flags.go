package run

import "flag"

var (
	showHelpShort    *bool
	showVersionShort *bool
	port             *string
	address          *string
	dataDir          *string
	configDirFlag    *string
	cacheDirFlag     *string
	logDirFlag       *string
	backupDirFlag    *string
	pidFileFlag      *string
	baseurlFlag      *string
	showVersion      *bool
	showStatus       *bool
	showHelp         *bool
	debugMode        *bool
	i2pEnabledFlag   *bool
	daemonMode       *bool
	colorMode        *string
	langFlag         *string
	serviceCmd       *string
	maintenanceCmd   *string
	includeSSLFlag   *bool
	includeDataFlag  *bool
	shellCmd         *string
	modeFlag         *string
	updateCmd        *string
)

// RegisterFlags adds the supported application flags to the command's flag set.
func RegisterFlags(flags *flag.FlagSet) {
	showHelpShort = flags.Bool("h", false, "Show help")
	showVersionShort = flags.Bool("v", false, "Show version information")
	port = flags.String("port", "", "Server port (overrides config)")
	address = flags.String("address", "", "Server address (overrides config)")
	dataDir = flags.String("data", "", "Data directory")
	configDirFlag = flags.String("config", "", "Configuration directory")
	cacheDirFlag = flags.String("cache", "", "Cache directory")
	logDirFlag = flags.String("log", "", "Log directory")
	backupDirFlag = flags.String("backup", "", "Backup directory")
	pidFileFlag = flags.String("pid", "", "PID file path")
	baseurlFlag = flags.String("baseurl", "/", "URL path prefix (default: /)")
	showVersion = flags.Bool("version", false, "Show version information")
	showStatus = flags.Bool("status", false, "Check server status (for health checks)")
	showHelp = flags.Bool("help", false, "Show help")
	debugMode = flags.Bool("debug", false, "Enable debug mode")
	i2pEnabledFlag = flags.Bool("i2p", false, "Enable the optional I2P eepsite")
	daemonMode = flags.Bool("daemon", false, "Run as daemon (detach from terminal)")
	colorMode = flags.String("color", "auto", "Color output: auto, yes, no")
	langFlag = flags.String("lang", "", "Language for output (default: auto-detect from LANG env)")
	serviceCmd = flags.String("service", "", "Service commands: start, stop, restart, reload, --install, --uninstall, --disable, --help")
	maintenanceCmd = flags.String("maintenance", "", "Maintenance commands: backup, restore, update, mode, setup, pgp, secret, security, token, data, compliance, scheduler, email, tor")
	includeSSLFlag = flags.Bool("include-ssl", false, "Include SSL/TLS private keys in backup (default: excluded)")
	includeDataFlag = flags.Bool("include-data", false, "Include full data directory in backup (default: excluded)")
	shellCmd = flags.String("shell", "", "Shell integration: completions, init, --help")
	modeFlag = flags.String("mode", "", "Application mode: production, development, debug")
	updateCmd = flags.String("update", "", "Update commands: check, yes, branch {stable|beta|devel}")
}

// RewriteBareUpdateArgs makes a bare --update equivalent to --update yes.
func RewriteBareUpdateArgs(args []string) []string {
	for i, arg := range args {
		if arg != "--update" && arg != "-update" {
			continue
		}
		if i == len(args)-1 || len(args) > i+1 && len(args[i+1]) > 0 && args[i+1][0] == '-' {
			rewritten := make([]string, 0, len(args)+1)
			rewritten = append(rewritten, args[:i+1]...)
			rewritten = append(rewritten, "yes")
			rewritten = append(rewritten, args[i+1:]...)
			return rewritten
		}
		break
	}
	return args
}
