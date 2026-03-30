package main

import (
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultRateLimit = 20.0 // Default: 20 requests per second per IP (allows normal browsing, prevents abuse)
)

var (
	appVersion     = "1.2.8"
	port           string
	ip             string
	showHidden     bool
	hash           bool
	maxHashSize    int64
	bandwidthLimit string
	colours        string
	rateLimit      float64 = -1 // -1 means use default, 0 means disable, >0 means use this value
	reload         bool
	idle           string // Idle timeout (empty = disabled, "15m" = default when flag is set)
	publicURL      string // Public base URL for links when behind a reverse proxy (--url)
	namePrefix     string
	nameSuffix     string
	statusURLFlag  string // shareplane status --url
	shareTTL       string
	byteLimitTotal string
	maxDlCount     int64
	whitelistIPs   string
	blacklistIPs   string
	basicUser      string
	basicPassword  string
	enableQR       bool
	enableWebDAV   bool
	encryptPass    string
	logFilePath    string
	singleStream   bool
	statsPage      bool
	useHTTPS       bool
	tlsCertFile    string
	tlsKeyFile     string
	enableTUI      bool
)

func main() {
	// Setup signal handling to print stats on exit
	setupSignalHandling()

	rootCmd := &cobra.Command{
		Use:   "shareplane [FILES...]",
		Short: "Simple HTTP Server - Serve files over HTTP",
		Long:  "A lightweight HTTP server written in Go for serving files and directories over HTTP. Perfect for quick file sharing.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				cmd.SilenceUsage = true
				return fmt.Errorf("no files or directories specified\n\nYou must specify at least one file or directory to serve.\n\nExample usage:\n  shareplane file.txt\n  shareplane /path/to/directory\n  shareplane file1.txt file2.txt\n\nUse 'shareplane --help' for more information")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			// Use environment variables if flags are not explicitly set
			if !cmd.Flags().Changed("port") {
				if envPort := os.Getenv("PORT"); envPort != "" {
					port = envPort
				}
			}
			if !cmd.Flags().Changed("ip") {
				if envIP := os.Getenv("IP"); envIP != "" {
					ip = envIP
				}
			}
			// Parse bandwidth limit
			var limitBytesPerSec int64
			if bandwidthLimit != "" {
				parsed, err := parseBandwidthLimit(bandwidthLimit)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: invalid bandwidth limit '%s': %v\n", bandwidthLimit, err)
					os.Exit(1)
				}
				limitBytesPerSec = parsed
			}
			// Parse colors
			var colorScheme *colorScheme
			if colours != "" {
				parsed, err := parseColors(colours)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: invalid colors '%s': %v\n", colours, err)
					fmt.Fprintf(os.Stderr, "Expected 7 colors: Background,Text,TableHeaderBg,TableHeaderText,TableBg,TableFilenameText,TableOtherText\n")
					os.Exit(1)
				}
				colorScheme = parsed
			}
			// Initialize rate limiter
			// -1 means use default, 0 means disable, >0 means use this value
			rateLimiterMutex.Lock()
			var limitValue float64
			if rateLimit < 0 {
				// Use default
				limitValue = defaultRateLimit
			} else if rateLimit == 0 {
				// Explicitly disabled
				limitValue = 0
			} else {
				// Use specified value
				limitValue = rateLimit
			}

			if limitValue > 0 {
				globalRateLimiter = newRateLimiter(limitValue)
			} else {
				globalRateLimiter = nil
			}
			rateLimiterMutex.Unlock()

			// Set version for files.go
			setAppVersion(appVersion)

			// Parse idle timeout if specified
			var idleTimeout time.Duration
			if cmd.Flags().Changed("idle") {
				// Flag was set, parse it (empty string means default 15m)
				parsed, err := parseIdleTimeout(idle)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: invalid idle timeout '%s': %v\n", idle, err)
					os.Exit(1)
				}
				idleTimeout = parsed
			}

			normalizedPublicURL, err := normalizePublicURL(publicURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid --url: %v\n", err)
				os.Exit(1)
			}

			serverCfg.TTLDeadline = time.Time{}
			serverCfg.ByteLimit = 0
			serverCfg.MaxDownloadPerFile = 0
			serverCfg.WhitelistIPs = nil
			serverCfg.BlacklistIPs = nil
			serverCfg.BasicUser = ""
			serverCfg.BasicPass = ""
			serverCfg.EnableQR = enableQR
			serverCfg.EnableWebDAV = enableWebDAV
			serverCfg.EncryptPassword = encryptPass
			serverCfg.EnableSingleStream = singleStream
			serverCfg.EnableStatsPage = statsPage
			serverCfg.EphemeralTLS = useHTTPS
			serverCfg.TLSCertFile = tlsCertFile
			serverCfg.TLSKeyFile = tlsKeyFile
			serverCfg.EnableTUI = enableTUI

			if (tlsCertFile != "") != (tlsKeyFile != "") {
				fmt.Fprintf(os.Stderr, "Error: --cert and --key must be set together\n")
				os.Exit(1)
			}

			if err := initServerLog(logFilePath); err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot open log file: %v\n", err)
				os.Exit(1)
			}
			defer closeServerLog()
			if enableTUI {
				tuiServerOutput(logFilePath)
			}

			if shareTTL != "" {
				parsed, err := parseShareTTL(shareTTL)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: invalid --ttl %q: %v\n", shareTTL, err)
					os.Exit(1)
				}
				serverCfg.TTLDeadline = time.Now().Add(parsed)
			}
			if byteLimitTotal != "" {
				parsed, err := parseTotalByteLimit(byteLimitTotal)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: invalid --byte-limit %q: %v\n", byteLimitTotal, err)
					os.Exit(1)
				}
				serverCfg.ByteLimit = parsed
			}
			if maxDlCount > 0 {
				serverCfg.MaxDownloadPerFile = maxDlCount
			}
			serverCfg.WhitelistIPs = parseCommaIPs(whitelistIPs)
			serverCfg.BlacklistIPs = parseCommaIPs(blacklistIPs)
			serverCfg.BasicUser = basicUser
			serverCfg.BasicPass = basicPassword

			serveFiles(args, ip, port, showHidden, hash, maxHashSize, limitBytesPerSec, colorScheme, reload, idleTimeout, normalizedPublicURL, namePrefix, nameSuffix)
		},
	}

	rootCmd.Version = appVersion
	rootCmd.SetVersionTemplate("shareplane version {{.Version}}\n")

	rootCmd.Flags().StringVar(&port, "port", "8080", "Port to listen on")
	rootCmd.Flags().StringVar(&ip, "ip", "0.0.0.0", "IP address to bind to (default is all interfaces)")
	rootCmd.Flags().BoolVar(&showHidden, "show-hidden", false, "Show files and directories starting with a dot (.) (hidden files are hidden by default)")
	rootCmd.Flags().BoolVar(&hash, "hash", false, "Calculate and display SHA1 hash for files in the listing")
	rootCmd.Flags().Int64Var(&maxHashSize, "max-hash-size", 0, "Maximum file size (in bytes) to calculate hash for (0 = no limit, default: 0)")
	rootCmd.Flags().StringVar(&bandwidthLimit, "bw-limit", "", "Bandwidth limit (e.g., 5MB, 250KB, 5M, 1.4G, or plain bytes). No limit if not specified.")
	rootCmd.Flags().Float64Var(&rateLimit, "rate-limit", -1, "Rate limit: maximum requests per second per IP address (default: 20, use 0 to disable). Recommended: 10-30 for normal use, higher for automated tools.")
	rootCmd.Flags().BoolVar(&reload, "reload", false, "Enable auto-reload: monitor files for changes in real-time using file system notifications (new files, removed files, modified files)")
	rootCmd.Flags().StringVar(&colours, "colours", "", "Color scheme: Background,Text,TableHeaderBg,TableHeaderText,TableBg,TableFilenameText,TableOtherText (comma-separated, 7 colors)")
	rootCmd.Flags().StringVar(&idle, "idle", "", "Idle timeout: server shuts down after this period of inactivity. Default: 15m if flag is set without value. Supports units: M (minutes), H (hours), D (days), W (weeks), Mo (months). Examples: 15m, 1H, 4D, 1W, 1Mo")
	rootCmd.Flags().StringVar(&publicURL, "url", "", "Public base URL for generated links (e.g. https://files.example.com:8443) when behind a reverse proxy; omit scheme to default to http")
	rootCmd.Flags().StringVar(&namePrefix, "prefix", "", "Optional prefix shown before each filename in listings (display only; URLs unchanged)")
	rootCmd.Flags().StringVar(&nameSuffix, "suffix", "", "Optional suffix shown after each filename in listings (display only; URLs unchanged)")
	rootCmd.Flags().StringVar(&shareTTL, "ttl", "", "Stop sharing after this duration from launch (plain number = minutes; or units: m, minutes, h, hours, d, days, w, weeks, mo). No persistence.")
	rootCmd.Flags().StringVar(&byteLimitTotal, "byte-limit", "", "Stop serving after this many total bytes transferred (same units as --bw-limit; no limit if unset)")
	rootCmd.Flags().Int64Var(&maxDlCount, "max-count", 0, "Maximum completed downloads per file (0 = unlimited)")
	rootCmd.Flags().StringVar(&whitelistIPs, "whitelist", "", "Comma-separated client IPs or CIDRs allowed (uses proxy-aware IP; empty = allow all)")
	rootCmd.Flags().StringVar(&blacklistIPs, "blacklist", "", "Comma-separated client IPs or CIDRs denied (uses proxy-aware IP)")
	rootCmd.Flags().StringVar(&basicUser, "basic-user", "", "HTTP Basic auth username (optional; empty = omit username check)")
	rootCmd.Flags().StringVar(&basicPassword, "basic-password", "", "HTTP Basic auth password (optional; empty = omit password check)")
	rootCmd.Flags().BoolVar(&enableQR, "qr", false, "Show QR code buttons for direct download links in the listing")
	rootCmd.Flags().BoolVar(&enableWebDAV, "webdav", false, "Serve WebDAV at /webdav/ (first shared path only)")
	rootCmd.Flags().StringVar(&encryptPass, "encrypt", "", "Password for encrypted downloads (AES-GCM over zstd; max 64 MiB per file; Range not supported)")
	rootCmd.Flags().StringVar(&logFilePath, "log", "", "Append server output to this file as well as stdout")
	rootCmd.Flags().BoolVar(&singleStream, "single-stream", false, "Enable GET /archive (zstd or tar.gz) and listing checkboxes for multi-file download")
	rootCmd.Flags().BoolVar(&statsPage, "stats", false, "Expose GET /stats with the same JSON as /api/status")
	rootCmd.Flags().BoolVar(&useHTTPS, "https", false, "Serve HTTPS with an ephemeral self-signed certificate (not saved; browser warnings expected)")
	rootCmd.Flags().StringVar(&tlsCertFile, "cert", "", "Path to TLS certificate (PEM); use with --key (takes precedence over --https)")
	rootCmd.Flags().StringVar(&tlsKeyFile, "key", "", "Path to TLS private key (PEM); use with --cert")
	rootCmd.Flags().BoolVar(&enableTUI, "tui", false, "Show live /api/status in the terminal (server runs in background; use --log to capture server output to a file)")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Print live download stats from a running shareplane server",
		Long:  "Fetches GET /api/status. Use --url or set SHAREPLANE_URL to the server base URL (default http://127.0.0.1:8080).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShareplaneStatus(statusURLFlag)
		},
	}
	statusCmd.Flags().StringVar(&statusURLFlag, "url", "", "Base URL of shareplane (default: SHAREPLANE_URL or http://127.0.0.1:8080)")
	rootCmd.AddCommand(statusCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// parseBandwidthLimit parses a bandwidth limit string and returns bytes per second.
// Supports formats like: "5MB", "250KB", "5M", "250K", "1.4G", or plain bytes "1048576"
func parseBandwidthLimit(limit string) (int64, error) {
	limit = strings.TrimSpace(limit)
	if limit == "" {
		return 0, fmt.Errorf("empty limit")
	}

	// Try to parse as plain number (bytes)
	if val, err := strconv.ParseInt(limit, 10, 64); err == nil {
		return val, nil
	}

	// Parse with unit (e.g., "5MB", "1.4G", "250KB")
	// Match pattern: optional decimal number, optional unit (case insensitive)
	re := regexp.MustCompile(`(?i)^([\d.]+)\s*([KMGT]?B?)$`)
	matches := re.FindStringSubmatch(limit)
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid format, expected number with optional unit (e.g., 5MB, 1.4G, 250KB)")
	}

	valueStr := matches[1]
	unit := strings.ToUpper(matches[2])

	// Parse the numeric value (supports decimals like 1.4)
	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}

	// Normalize unit (handle both "M" and "MB", "K" and "KB", etc.)
	if unit == "" {
		return int64(value), nil
	}

	// Remove trailing 'B' if present (5MB = 5M, 250KB = 250K)
	if len(unit) > 1 && unit[len(unit)-1] == 'B' {
		unit = unit[:len(unit)-1]
	}

	// Convert to bytes per second
	var multiplier float64
	switch unit {
	case "K":
		multiplier = 1024
	case "M":
		multiplier = 1024 * 1024
	case "G":
		multiplier = 1024 * 1024 * 1024
	case "T":
		multiplier = 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown unit '%s', supported units: K, M, G, T (or KB, MB, GB, TB)", unit)
	}

	return int64(value * multiplier), nil
}

// parseIdleTimeout parses an idle timeout string and returns a time.Duration.
// Supports formats like: "15m", "1H", "4D", "1W", "1Mo" or plain minutes "15"
// If empty string is provided, returns 15 minutes (default when flag is set)
func parseIdleTimeout(timeout string) (time.Duration, error) {
	timeout = strings.TrimSpace(timeout)
	if timeout == "" {
		// Default to 15 minutes when flag is set without value
		return 15 * time.Minute, nil
	}

	// Try to parse as plain number (minutes)
	if val, err := strconv.ParseFloat(timeout, 64); err == nil {
		return time.Duration(val) * time.Minute, nil
	}

	// Parse with unit (e.g., "15m", "1H", "4D", "1W", "1Mo")
	// Match pattern: optional decimal number, unit (case insensitive)
	// Note: "Mo" must come before "M" in the alternation to match months correctly
	re := regexp.MustCompile(`(?i)^([\d.]+)\s*(Mo|[MHDW])$`)
	matches := re.FindStringSubmatch(timeout)
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid format, expected number with unit (e.g., 15m, 1H, 4D, 1W, 1Mo)")
	}

	valueStr := matches[1]
	unit := strings.ToUpper(matches[2])

	// Parse the numeric value (supports decimals like 1.5)
	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}

	// Convert to time.Duration
	var multiplier time.Duration
	switch unit {
	case "M":
		multiplier = time.Minute
	case "H":
		multiplier = time.Hour
	case "D":
		multiplier = 24 * time.Hour
	case "W":
		multiplier = 7 * 24 * time.Hour
	case "MO":
		multiplier = 30 * 24 * time.Hour // Approximate month as 30 days
	default:
		return 0, fmt.Errorf("unsupported unit: %s (supported: M, H, D, W, Mo)", unit)
	}

	return time.Duration(value * float64(multiplier)), nil
}

// parseShareTTL parses --ttl: plain number = minutes; or 10M, 1H, 3D, 12Weeks, 1mo, etc.
func parseShareTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(v * float64(time.Minute)), nil
	}
	re := regexp.MustCompile(`(?i)^([\d.]+)\s*(weeks|minutes|hours|days|mo|[mhdw])$`)
	matches := re.FindStringSubmatch(s)
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid TTL; use e.g. 30, 10m, 1H, 3D, 12Weeks")
	}
	val, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, err
	}
	u := strings.ToLower(matches[2])
	switch u {
	case "m", "minutes":
		return time.Duration(val * float64(time.Minute)), nil
	case "h", "hours":
		return time.Duration(val * float64(time.Hour)), nil
	case "d", "days":
		return time.Duration(val * 24 * float64(time.Hour)), nil
	case "w", "week", "weeks":
		return time.Duration(val * 7 * 24 * float64(time.Hour)), nil
	case "mo":
		return time.Duration(val * 30 * 24 * float64(time.Hour)), nil
	default:
		return 0, fmt.Errorf("unknown unit %q", u)
	}
}

// parseTotalByteLimit parses total byte cap (same units as --bw-limit).
func parseTotalByteLimit(s string) (int64, error) {
	return parseBandwidthLimit(s)
}

// normalizePublicURL validates --url and returns a base URL without a trailing slash (or empty).
func normalizePublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("missing host")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

// colorScheme holds the color configuration for the HTML output
type colorScheme struct {
	Background        string
	Text              string
	TableHeaderBg     string
	TableHeaderText   string
	TableBg           string
	TableFilenameText string
	TableOtherText    string
}

// parseColors parses a comma-separated string of 7 colors
func parseColors(colorStr string) (*colorScheme, error) {
	colors := strings.Split(colorStr, ",")
	if len(colors) != 7 {
		return nil, fmt.Errorf("expected 7 colors, got %d", len(colors))
	}

	// Validate colors (basic hex color validation)
	colorRegex := regexp.MustCompile(`^#?[0-9A-Fa-f]{6}$|^[a-zA-Z]+$`)
	hexOnlyRegex := regexp.MustCompile(`^[0-9A-Fa-f]{6}$`)
	for i, color := range colors {
		color = strings.TrimSpace(color)
		if color == "" {
			return nil, fmt.Errorf("color %d is empty", i+1)
		}
		// Allow hex colors (#RRGGBB or RRGGBB) or named colors
		if !colorRegex.MatchString(color) && !isValidColorName(color) {
			return nil, fmt.Errorf("invalid color format at position %d: '%s' (expected hex like #FF0000 or named color)", i+1, color)
		}
		// Normalize hex colors to include #
		if hexOnlyRegex.MatchString(color) {
			colors[i] = "#" + color
		} else {
			colors[i] = color
		}
	}

	return &colorScheme{
		Background:        strings.TrimSpace(colors[0]),
		Text:              strings.TrimSpace(colors[1]),
		TableHeaderBg:     strings.TrimSpace(colors[2]),
		TableHeaderText:   strings.TrimSpace(colors[3]),
		TableBg:           strings.TrimSpace(colors[4]),
		TableFilenameText: strings.TrimSpace(colors[5]),
		TableOtherText:    strings.TrimSpace(colors[6]),
	}, nil
}

// isValidColorName checks if a string is a valid CSS color name
func isValidColorName(name string) bool {
	validColors := map[string]bool{
		"black": true, "white": true, "red": true, "green": true, "blue": true,
		"yellow": true, "cyan": true, "magenta": true, "gray": true, "grey": true,
		"orange": true, "purple": true, "pink": true, "brown": true, "navy": true,
		"teal": true, "lime": true, "maroon": true, "olive": true, "silver": true,
		"aqua": true, "fuchsia": true, "transparent": true,
	}
	return validColors[strings.ToLower(name)]
}

func setupSignalHandling() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		// Cleanup rate limiter
		rateLimiterMutex.Lock()
		if globalRateLimiter != nil {
			globalRateLimiter.stop()
		}
		rateLimiterMutex.Unlock()

		// Cleanup file watcher
		fileWatcherMutex.Lock()
		if globalFileWatcher != nil {
			globalFileWatcher.stop()
		}
		fileWatcherMutex.Unlock()

		printStats()
		os.Exit(0)
	}()
}
