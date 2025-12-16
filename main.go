package main

import (
	"fmt"
	"os"
	"os/signal"
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
			serveFiles(args, ip, port, showHidden, hash, maxHashSize)
		},
	}

	rootCmd.Version = appVersion
	rootCmd.SetVersionTemplate("shs version {{.Version}}\n")

	rootCmd.Flags().StringVar(&port, "port", "8080", "Port to listen on")
	rootCmd.Flags().StringVar(&ip, "ip", "0.0.0.0", "IP address to bind to (default is all interfaces)")
	rootCmd.Flags().BoolVar(&showHidden, "show-hidden", false, "Show files and directories starting with a dot (.) (hidden files are hidden by default)")
	rootCmd.Flags().BoolVar(&hash, "hash", false, "Calculate and display SHA1 hash for files in the listing")
	rootCmd.Flags().Int64Var(&maxHashSize, "max-hash-size", 0, "Maximum file size (in bytes) to calculate hash for (0 = no limit, default: 0)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
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
