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

var (
	appVersion  = "1.1.73"
	port        string
	ip          string
	showHidden  bool
	hash        bool
	maxHashSize int64
	bandwidthLimit string
)

func main() {
	// Setup signal handling to print stats on exit
	setupSignalHandling()

	rootCmd := &cobra.Command{
		Use:   "shs [FILES...]",
		Short: "Simple HTTP Server - Serve files over HTTP",
		Long:  "A lightweight HTTP server written in Go for serving files and directories over HTTP. Perfect for quick file sharing.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				cmd.SilenceUsage = true
				return fmt.Errorf("no files or directories specified\n\nYou must specify at least one file or directory to serve.\n\nExample usage:\n  shs file.txt\n  shs /path/to/directory\n  shs file1.txt file2.txt\n\nUse 'shs --help' for more information")
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
			serveFiles(args, ip, port, showHidden, hash, maxHashSize, limitBytesPerSec)
		},
	}

	rootCmd.Version = appVersion
	rootCmd.SetVersionTemplate("shs version {{.Version}}\n")

	rootCmd.Flags().StringVar(&port, "port", "8080", "Port to listen on")
	rootCmd.Flags().StringVar(&ip, "ip", "0.0.0.0", "IP address to bind to (default is all interfaces)")
	rootCmd.Flags().BoolVar(&showHidden, "show-hidden", false, "Show files and directories starting with a dot (.) (hidden files are hidden by default)")
	rootCmd.Flags().BoolVar(&hash, "hash", false, "Calculate and display SHA1 hash for files in the listing")
	rootCmd.Flags().Int64Var(&maxHashSize, "max-hash-size", 0, "Maximum file size (in bytes) to calculate hash for (0 = no limit, default: 0)")
	rootCmd.Flags().StringVar(&bandwidthLimit, "limit", "", "Bandwidth limit (e.g., 5MB, 250KB, 5M, 1.4G, or plain bytes). No limit if not specified.")

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

func setupSignalHandling() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		printStats()
		os.Exit(0)
	}()
}
