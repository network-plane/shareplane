package main

import (
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

const (
	defaultRateLimit = 20.0 // Default: 20 requests per second per IP (allows normal browsing, prevents abuse)
)

var (
	appVersion     = "1.1.73"
	port           string
	ip             string
	showHidden     bool
	hash           bool
	maxHashSize    int64
	bandwidthLimit string
	colours        string
	rateLimit      float64 = -1 // -1 means use default, 0 means disable, >0 means use this value
	reload         bool
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

			serveFiles(args, ip, port, showHidden, hash, maxHashSize, limitBytesPerSec, colorScheme, reload)
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

// colorScheme holds the color configuration for the HTML output
type colorScheme struct {
	Background         string
	Text               string
	TableHeaderBg      string
	TableHeaderText    string
	TableBg            string
	TableFilenameText  string
	TableOtherText     string
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
