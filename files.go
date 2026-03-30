package main

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// serverPublicBaseURL is set from --url (no trailing slash). Empty means use the HTTP request host for generated links.
var serverPublicBaseURL string

// serverNamePrefix and serverNameSuffix are set from --prefix / --suffix (display labels only; URLs still use displayName).
var serverNamePrefix, serverNameSuffix string

// getRealIP extracts the real client IP from the request, handling proxy headers
// Checks headers in order: X-Forwarded-For, X-Real-IP, X-Forwarded, CF-Connecting-IP
// Falls back to RemoteAddr if no proxy headers are present
func getRealIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common, can contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
		// The first one is the original client IP
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP header (common in nginx and other proxies)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Check X-Forwarded header
	if xf := r.Header.Get("X-Forwarded"); xf != "" {
		// X-Forwarded format: "for=192.0.2.60;proto=http;by=203.0.113.43"
		parts := strings.Split(xf, ";")
		for _, part := range parts {
			if strings.HasPrefix(part, "for=") {
				ip := strings.TrimPrefix(part, "for=")
				ip = strings.TrimSpace(ip)
				// Remove port if present (for=192.0.2.60:12345)
				if idx := strings.LastIndex(ip, ":"); idx > 0 {
					ip = ip[:idx]
				}
				if ip != "" {
					return ip
				}
			}
		}
	}

	// Check CF-Connecting-IP (Cloudflare)
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return strings.TrimSpace(cfip)
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, RemoteAddr might not have a port
		return r.RemoteAddr
	}
	return ip
}

// copyClientsSnapshot returns a sorted copy of per-client full/partial stats (for JSON APIs).
func copyClientsSnapshot() []apiDownloadClient {
	perClientMu.Lock()
	defer perClientMu.Unlock()
	ips := make([]string, 0, len(perClientFileStats))
	for ip := range perClientFileStats {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	clients := make([]apiDownloadClient, 0, len(ips))
	for _, ip := range ips {
		m := perClientFileStats[ip]
		paths := make([]string, 0, len(m))
		for p := range m {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		files := make([]apiDownloadFile, 0, len(paths))
		for _, p := range paths {
			st := m[p]
			files = append(files, apiDownloadFile{Path: p, Full: st.Full, Partial: st.Partial})
		}
		clients = append(clients, apiDownloadClient{IP: ip, Files: files})
	}
	return clients
}

func buildAPIStatusResponse() apiStatusResponse {
	statsMutex.Lock()
	paths := make([]string, 0, len(downloadStats))
	for p := range downloadStats {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	files := make([]apiStatusFile, 0, len(paths))
	var totalDL int64
	for _, p := range paths {
		s := downloadStats[p]
		totalDL += s.Bytes
		files = append(files, apiStatusFile{Path: p, Count: s.Count, Bytes: s.Bytes})
	}
	listing := totalBytesSentForListings
	statsMutex.Unlock()

	return apiStatusResponse{
		Version:            getAppVersion(),
		TotalDownloadBytes: totalDL,
		TotalListingBytes:  listing,
		Files:              files,
		Clients:            copyClientsSnapshot(),
	}
}

func serveFile(w http.ResponseWriter, r *http.Request, bandwidthLimit int64, validatedPath string, mode string) {
	clientIP := getRealIP(r)
	isHEAD := r.Method == "HEAD"

	// Default behavior is download unless explicitly overridden.
	switch mode {
	case "", "download":
		filename := filepath.Base(validatedPath)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	case "play":
		// Let browser play/render inline based on content type.
	case "preview":
		// Inline in browser (images, PDF, text, etc.); no attachment header.
	case "stream":
		// Serve an M3U playlist pointing to the inline-play URL so external
		// players (VLC/mpv/etc.) can open the stream reliably across browsers.
		var streamURL string
		if serverPublicBaseURL != "" {
			streamURL = serverPublicBaseURL + r.URL.Path + "?mode=play"
		} else {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			streamURL = fmt.Sprintf("%s://%s%s?mode=play", scheme, r.Host, r.URL.Path)
		}
		filename := filepath.Base(validatedPath)
		w.Header().Set("Content-Type", "audio/x-mpegurl; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename+".m3u"))
		if isHEAD {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = fmt.Fprintf(w, "#EXTM3U\n#EXTINF:-1,%s\n%s\n", filename, streamURL)
		return
	default:
		// Unknown mode falls back to safe default (download).
		filename := filepath.Base(validatedPath)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	}

	// Apply bandwidth limiting if specified (not needed for HEAD requests)
	finalWriter := http.ResponseWriter(w)
	if bandwidthLimit > 0 && !isHEAD {
		finalWriter = &rateLimitedWriter{
			ResponseWriter: w,
			bytesPerSecond: bandwidthLimit,
			lastWrite:      time.Now(),
		}
	}

	// Determine the file size
	fileInfo, err := os.Stat(validatedPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	fileSize := fileInfo.Size()

	// Check if this is a Range request (for resuming downloads or partial fetches)
	isRangeRequest := r.Header.Get("Range") != ""

	// Only wrap with countingWriter if not HEAD (HEAD requests don't send body, so no need to count)
	var cw *countingWriter
	if !isHEAD {
		// Use relative path for logging to avoid leaking full paths
		relPath := getRelativePath(validatedPath, allowedPaths)
		cw = &countingWriter{
			ResponseWriter: finalWriter,
			path:             relPath,
			clientIP:         clientIP,
			isRangeRequest:   isRangeRequest,
			fileSize:         fileSize,
		}
		finalWriter = cw
	}

	// http.ServeFile automatically handles HTTP Range requests (206 Partial Content)
	// and HEAD requests (returns headers only, no body)
	// This enables resuming downloads, partial file fetches, and probing files without downloading
	// Use validatedPath to ensure we only serve allowed files
	http.ServeFile(finalWriter, r, validatedPath)
	
	// Only track stats and check completion for non-HEAD requests
	if !isHEAD && cw != nil {
		cw.finish()

		// Check if the download was complete (only warn for non-Range requests)
		// Range requests intentionally send fewer bytes, so don't warn for those
		if !isRangeRequest && cw.bytesWritten < fileSize {
			relPath := getRelativePath(validatedPath, allowedPaths)
			fmt.Printf("Warning: File %s was not fully downloaded. Sent %d bytes out of %d total bytes.\n", relPath, cw.bytesWritten, fileSize)
		}
	}
}

// updateLastActivity updates the last activity timestamp (thread-safe)
func updateLastActivity() {
	lastActivityMu.Lock()
	lastActivity = time.Now()
	lastActivityMu.Unlock()
}

// serveFiles sets up the HTTP server and handlers.
func serveFiles(filePaths []string, ip string, port string, showHidden bool, hash bool, maxHashSize int64, bandwidthLimit int64, colorScheme *colorScheme, enableReload bool, idleTimeout time.Duration, publicBaseURL string, namePrefix string, nameSuffix string) {
	serverPublicBaseURL = publicBaseURL
	serverNamePrefix = namePrefix
	serverNameSuffix = nameSuffix
	// Initialize allowed paths for security validation
	if err := initAllowedPaths(filePaths); err != nil {
		fmt.Printf("Error initializing allowed paths: %v\n", err)
		os.Exit(1)
	}
	
	// Set up idle timeout tracking
	if idleTimeout > 0 {
		// Initialize last activity to now
		updateLastActivity()
		
		// Start idle timeout checker
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			
			for range ticker.C {
				lastActivityMu.RLock()
				last := lastActivity
				lastActivityMu.RUnlock()

				if time.Since(last) >= idleTimeout {
					fmt.Printf("\n[Idle Timeout] No activity for %v, shutting down server...\n", idleTimeout)
					
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

					// Shutdown HTTP server gracefully
					httpServerMu.RLock()
					server := httpServer
					httpServerMu.RUnlock()

					if server != nil {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						if err := server.Shutdown(ctx); err != nil {
							fmt.Printf("[Idle Timeout] Error shutting down server: %v\n", err)
						}
						cancel()
					}
					
					printStats()
					os.Exit(0)
				}
			}
		}()
		
		fmt.Printf("[Idle Timeout] Server will shut down after %v of inactivity\n", idleTimeout)
	}
	
	// API endpoint for JSON data
	http.HandleFunc("/api/files", rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		updateLastActivity()
		// Get path parameter (optional, defaults to root)
		requestedPath := r.URL.Query().Get("path")
		
		var filesInfo []FileInfo
		var err error
		displayBasePath := ""
		useDisplayBasePath := false
		
		if requestedPath == "" {
			// Root path - list all shared files/directories
			filesInfo, err = listFiles(filePaths, showHidden, hash, maxHashSize)
		} else {
			// Validate path
			validatedPath, allowed := isPathAllowed(requestedPath)
			if !allowed {
				http.Error(w, "Path not found", http.StatusNotFound)
				return
			}
			
			var fileInfo os.FileInfo
			fileInfo, err = os.Stat(validatedPath)
			if err != nil {
				http.Error(w, "Path not found", http.StatusNotFound)
				return
			}
			
			if fileInfo.IsDir() {
				filesInfo, err = listFilesInDir(validatedPath, showHidden, hash, maxHashSize)
				displayBasePath = validatedPath
				useDisplayBasePath = true
			} else {
				// Single file
				filesInfo = []FileInfo{{
					Name:        validatedPath,
					DisplayName: getRelativePath(validatedPath, allowedPaths),
					Size:        fileInfo.Size(),
					ModTime:     fileInfo.ModTime(),
					IsDir:       false,
				}}
				err = nil
			}
		}
		
		if err != nil {
			http.Error(w, "Failed to list files", http.StatusInternalServerError)
			return
		}
		
		// Convert to display names and calculate totals
		displayFiles := make([]FileInfo, len(filesInfo))
		var totalSize int64
		var fileCount int
		
		for i, f := range filesInfo {
			displayFiles[i] = f
			if displayFiles[i].DisplayName == "" {
				if useDisplayBasePath {
					relPath, relErr := filepath.Rel(displayBasePath, f.Name)
					if relErr == nil && !strings.HasPrefix(relPath, "..") {
						// Use slash separators in URLs regardless of host OS.
						displayFiles[i].DisplayName = filepath.ToSlash(relPath)
					} else {
						displayFiles[i].DisplayName = getRelativePath(f.Name, allowedPaths)
					}
				} else {
					displayFiles[i].DisplayName = getRelativePath(f.Name, allowedPaths)
				}
			}
			
			// Check if it's a directory
			fileInfo, err := os.Stat(f.Name)
			if err == nil {
				displayFiles[i].IsDir = fileInfo.IsDir()
				if !fileInfo.IsDir() {
					totalSize += f.Size
					fileCount++
				}
			}
		}

		for i := range displayFiles {
			decorateFileDisplay(&displayFiles[i])
			if !displayFiles[i].IsDir {
				displayFiles[i].DownloadCount = lookupDownloadCount(displayFiles[i].DisplayName)
			}
		}
		
		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		response := apiResponse{
			Files:     displayFiles,
			TotalSize: totalSize,
			FileCount: fileCount,
			ShowHash:  hash,
		}
		
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	}, getRealIP))

	// API endpoint for searching files/directories by name
	http.HandleFunc("/api/search", rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		updateLastActivity()

		query := strings.TrimSpace(r.URL.Query().Get("q"))
		requestedPath := strings.TrimSpace(r.URL.Query().Get("path"))
		if query == "" {
			http.Error(w, "Missing search query", http.StatusBadRequest)
			return
		}

		// Determine search base paths.
		searchBases := make([]string, 0)
		useRelativeToBase := false

		if requestedPath == "" {
			searchBases = append(searchBases, allowedPaths...)
		} else {
			validatedPath, allowed := isPathAllowed(requestedPath)
			if !allowed {
				http.Error(w, "Path not found", http.StatusNotFound)
				return
			}

			info, err := os.Stat(validatedPath)
			if err != nil {
				http.Error(w, "Path not found", http.StatusNotFound)
				return
			}

			if info.IsDir() {
				searchBases = append(searchBases, validatedPath)
				useRelativeToBase = true
			} else {
				// If searching from a file path, search in its parent directory.
				searchBases = append(searchBases, filepath.Dir(validatedPath))
				useRelativeToBase = true
			}
		}

		filesInfo, err := searchFiles(searchBases, query, showHidden, hash, maxHashSize, useRelativeToBase)
		if err != nil {
			http.Error(w, "Failed to search files", http.StatusInternalServerError)
			return
		}

		var totalSize int64
		var fileCount int
		for _, f := range filesInfo {
			if !f.IsDir {
				totalSize += f.Size
				fileCount++
			}
		}

		for i := range filesInfo {
			decorateFileDisplay(&filesInfo[i])
			if !filesInfo[i].IsDir {
				filesInfo[i].DownloadCount = lookupDownloadCount(filesInfo[i].DisplayName)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		response := apiResponse{
			Files:     filesInfo,
			TotalSize: totalSize,
			FileCount: fileCount,
			ShowHash:  hash,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	}, getRealIP))

	// GET /api/downloads — per-client IP: which files were fetched in full vs partial (Range/incomplete)
	http.HandleFunc("/api/downloads", rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		updateLastActivity()
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		clients := copyClientsSnapshot()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(apiDownloadsResponse{Clients: clients})
	}, getRealIP))

	// GET /api/status — aggregate download and listing stats (for scripts and shareplane status)
	http.HandleFunc("/api/status", rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		updateLastActivity()
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(buildAPIStatusResponse())
	}, getRealIP))

	// GET /verify?file=relative/path — returns JSON with SHA1 for a single shared file
	http.HandleFunc("/verify", rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		updateLastActivity()
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := strings.TrimSpace(r.URL.Query().Get("file"))
		if q == "" {
			q = strings.TrimSpace(r.URL.Query().Get("path"))
		}
		if q == "" {
			http.Error(w, "Missing file or path query parameter", http.StatusBadRequest)
			return
		}
		validatedPath, allowed := isPathAllowed(q)
		if !allowed {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		info, err := os.Stat(validatedPath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		if info.IsDir() {
			http.Error(w, "Path is a directory, not a file", http.StatusBadRequest)
			return
		}
		hash, err := calculateSHA1(validatedPath)
		if err != nil {
			http.Error(w, "Failed to read file", http.StatusInternalServerError)
			return
		}
		rel := getRelativePath(validatedPath, allowedPaths)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(struct {
			SHA1 string `json:"sha1"`
			Path string `json:"path"`
		}{SHA1: hash, Path: rel})
	}, getRealIP))
	
	http.HandleFunc("/", rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		updateLastActivity()
		if r.URL.Path != "/" {
			// Strip the leading slash and validate path
			requestedPath := r.URL.Path[1:]
			decodedPath, err := url.PathUnescape(requestedPath)
			if err == nil {
				requestedPath = decodedPath
			}
			
			// SECURITY: Validate that the requested path is within allowed directories
			validatedPath, allowed := isPathAllowed(requestedPath)
			if !allowed {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
			
			fileInfo, err := os.Stat(validatedPath)
			if err != nil {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
			
			if fileInfo.IsDir() {
				// Handle HEAD requests for directories
				if r.Method == "HEAD" {
					// Return headers only for HEAD requests on directories
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					return
				}
				// It's a directory - serve the client-side HTML app with path parameter
				renderClientApp(w, hash, colorScheme, getAppVersion())
				return
			}
			// It's a file, serve it normally (validatedPath is already validated)
			mode := r.URL.Query().Get("mode")
			serveFile(w, r, bandwidthLimit, validatedPath, mode)
			return
		}
		// Root path - serve the client-side HTML app
		// Handle HEAD requests for root
		if r.Method == "HEAD" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			return
		}
		// Serve the client-side HTML that will fetch from /api/files
		renderClientApp(w, hash, colorScheme, getAppVersion())
	}, getRealIP))

	// Start file watcher if reload is enabled
	if enableReload {
		fileWatcherMutex.Lock()
		watcher, err := newFileWatcher(filePaths, showHidden)
		if err != nil {
			fmt.Printf("Warning: Failed to initialize file watcher: %v\n", err)
			fmt.Println("Auto-reload will not be available.")
		} else {
			globalFileWatcher = watcher
			globalFileWatcher.start()
			fmt.Println("Auto-reload enabled: monitoring files for changes in real-time...")
		}
		fileWatcherMutex.Unlock()
	}

	listenAddress := fmt.Sprintf("%s:%s", ip, port)

	// If listening on 0.0.0.0, show all available IP addresses
	if ip == "0.0.0.0" {
		fmt.Printf("Serving on http://%s\n", listenAddress)
		fmt.Println("Available on:")
		interfaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range interfaces {
				addrs, err := iface.Addrs()
				if err != nil {
					continue
				}
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
						if ipNet.IP.To4() != nil {
							fmt.Printf("  http://%s:%s\n", ipNet.IP.String(), port)
						}
					}
				}
			}
		}
		// Also show localhost
		fmt.Printf("  http://127.0.0.1:%s\n", port)
		fmt.Printf("  http://localhost:%s\n", port)
	} else {
		fmt.Printf("Serving on http://%s\n", listenAddress)
	}

	// Create HTTP server for graceful shutdown support
	server := &http.Server{
		Addr:    listenAddress,
		Handler: nil,
	}
	
	// Store server reference for idle timeout shutdown
	httpServerMu.Lock()
	httpServer = server
	httpServerMu.Unlock()
	
	// Start server with optional PROXY protocol parsing.
	// This allows real client IPs behind FRP TCP proxies (proxyProtocolVersion=v2)
	// while remaining compatible with direct/HTTP proxy traffic without PROXY headers.
	baseListener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatal(err)
	}
	proxyListener := &proxyproto.Listener{
		Listener:          baseListener,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if err := server.Serve(proxyListener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// isHidden checks if a file or directory name starts with a dot (hidden file).
func isHidden(name string) bool {
	base := filepath.Base(name)
	return len(base) > 0 && base[0] == '.'
}

// calculateSHA1 calculates the SHA1 hash of a file.
func calculateSHA1(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// listFilesInDir generates a slice of FileInfo for files in a specific directory.
func listFilesInDir(dirPath string, showHidden bool, hash bool, maxHashSize int64) ([]FileInfo, error) {
	var filesInfo []FileInfo
	
	fileInfo, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access directory: %w", err)
	}
	
	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("path is not a directory")
	}
	
	dirFiles, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory: %w", err)
	}
	
	for _, f := range dirFiles {
		// Skip hidden files unless showHidden flag is set
		if !showHidden && isHidden(f.Name()) {
			continue
		}
		
		fileInfo, err := f.Info()
		if err != nil {
			return nil, fmt.Errorf("cannot get file info: %w", err)
		}
		
		fullPath := filepath.Join(dirPath, f.Name())
		fileSize := fileInfo.Size()
		
		// Calculate hash if enabled and file size is within limit
		var hashValue string
		if hash && !fileInfo.IsDir() {
			if maxHashSize == 0 || fileSize <= maxHashSize {
				hash, err := calculateSHA1(fullPath)
				if err == nil {
					hashValue = hash
				}
			}
		}
		
		filesInfo = append(filesInfo, FileInfo{
			Name:        fullPath,
			DisplayName: "", // Will be set in API handler
			Size:        fileSize,
			ModTime:     fileInfo.ModTime(),
			Hash:        hashValue,
		})
	}
	
	return filesInfo, nil
}

// listFiles generates a slice of FileInfo for the given paths, including expanding glob patterns.
func listFiles(paths []string, showHidden bool, hash bool, maxHashSize int64) ([]FileInfo, error) {
	var filesInfo []FileInfo
	for _, pattern := range paths {
		expandedPaths, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern: %w", err)
		}
		if len(expandedPaths) == 0 {
			return nil, fmt.Errorf("no files or directories found")
		}
		for _, path := range expandedPaths {
			fileInfo, err := os.Stat(path)
			if err != nil {
				return nil, fmt.Errorf("cannot access path: %w", err)
			}
			if fileInfo.IsDir() {
				dirFiles, err := os.ReadDir(path)
				if err != nil {
					return nil, fmt.Errorf("cannot read directory: %w", err)
				}
				for _, f := range dirFiles {
					// Skip hidden files unless showHidden flag is set
					if !showHidden && isHidden(f.Name()) {
						continue
					}
					fileInfo, err := f.Info() // Get the FileInfo for the directory entry
					if err != nil {
						return nil, fmt.Errorf("cannot get file info: %w", err)
					}
					fullPath := filepath.Join(path, f.Name())
					fileSize := fileInfo.Size()

					// Calculate hash if enabled and file size is within limit
					var hashValue string
					if hash && !fileInfo.IsDir() {
						if maxHashSize == 0 || fileSize <= maxHashSize {
							hash, err := calculateSHA1(fullPath)
							if err == nil {
								hashValue = hash
							}
						}
					}

					filesInfo = append(filesInfo, FileInfo{
						Name:    fullPath,
						Size:    fileSize,
						ModTime: fileInfo.ModTime(),
						Hash:    hashValue,
					})
				}

			} else {
				// Skip hidden files unless showHidden flag is set
				if !showHidden && isHidden(path) {
					continue
				}
				fileSize := fileInfo.Size()

				// Calculate hash if enabled and file size is within limit
				var hashValue string
				if hash {
					if maxHashSize == 0 || fileSize <= maxHashSize {
						hash, err := calculateSHA1(path)
						if err == nil {
							hashValue = hash
						}
					}
				}

				filesInfo = append(filesInfo, FileInfo{
					Name:        path,
					DisplayName: "", // Will be set in API handler
					Size:        fileSize,
					ModTime:     fileInfo.ModTime(),
					Hash:        hashValue,
				})
			}
		}
	}
	return filesInfo, nil
}

// searchFiles recursively searches for entries whose filename contains query.
func searchFiles(basePaths []string, query string, showHidden bool, hash bool, maxHashSize int64, useRelativeToBase bool) ([]FileInfo, error) {
	queryLower := strings.ToLower(query)
	results := make([]FileInfo, 0, 128)
	seen := make(map[string]struct{})

	for _, base := range basePaths {
		baseInfo, err := os.Stat(base)
		if err != nil || !baseInfo.IsDir() {
			continue
		}

		walkErr := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if path == base {
				return nil
			}

			name := d.Name()
			if !showHidden && isHidden(name) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if !strings.Contains(strings.ToLower(name), queryLower) {
				return nil
			}

			absPath, err := filepath.Abs(path)
			if err != nil {
				return nil
			}
			absPath = filepath.Clean(absPath)
			if _, ok := seen[absPath]; ok {
				return nil
			}
			seen[absPath] = struct{}{}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			displayName := getRelativePath(absPath, allowedPaths)
			if useRelativeToBase {
				if rel, relErr := filepath.Rel(base, absPath); relErr == nil && !strings.HasPrefix(rel, "..") {
					displayName = filepath.ToSlash(rel)
				}
			}

			hashValue := ""
			if hash && !info.IsDir() {
				if maxHashSize == 0 || info.Size() <= maxHashSize {
					if h, hErr := calculateSHA1(absPath); hErr == nil {
						hashValue = h
					}
				}
			}

			results = append(results, FileInfo{
				Name:        absPath,
				DisplayName: displayName,
				Size:        info.Size(),
				ModTime:     info.ModTime(),
				Hash:        hashValue,
				IsDir:       info.IsDir(),
			})
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return strings.ToLower(results[i].DisplayName) < strings.ToLower(results[j].DisplayName)
	})

	return results, nil
}

// formatSize formats file size in human-readable format
func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// templateData holds data for the file listing template
type templateData struct {
	Files           []FileInfo
	ShowHash        bool
	ColorScheme     *colorScheme
	UseDefaultTheme bool
	TotalSize       int64
	FileCount       int
	Version         string
	PublicBaseURL   string // from --url; empty = use window.location.origin in the client
}

// globalAppVersion stores the application version (set by main.go)
var globalAppVersion = "1.1.75"

// setAppVersion sets the application version (called from main.go)
func setAppVersion(version string) {
	globalAppVersion = version
}

// getAppVersion returns the application version
func getAppVersion() string {
	return globalAppVersion
}

func decorateFileDisplay(f *FileInfo) {
	if serverNamePrefix == "" && serverNameSuffix == "" {
		f.PrettyName = ""
		return
	}
	if f.IsDir {
		base := strings.TrimSuffix(f.DisplayName, "/")
		f.PrettyName = serverNamePrefix + base + serverNameSuffix + "/"
		return
	}
	f.PrettyName = serverNamePrefix + f.DisplayName + serverNameSuffix
}

// renderClientApp renders the client-side HTML application that fetches data from the API
func renderClientApp(w http.ResponseWriter, showHash bool, colorScheme *colorScheme, version string) {
	cw := &countingWriter{ResponseWriter: w}
	tmpl := template.Must(template.New("clientApp").Funcs(template.FuncMap{
		"formatSize": formatSize,
	}).Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>File Listing</title>
    <style>
        body {
            font-family: monospace;
            margin: 20px;
            {{if .ColorScheme}}background-color: {{.ColorScheme.Background}};{{else}}background-color: var(--bg);{{end}}
        }
        h1 {
            {{if .ColorScheme}}color: {{.ColorScheme.Text}};{{else}}color: var(--text);{{end}}
        }
        table {
            border-collapse: collapse;
            width: 100%;
            {{if .ColorScheme}}background-color: {{.ColorScheme.TableBg}};{{else}}background-color: var(--table-bg);{{end}}
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th {
            {{if .ColorScheme}}background-color: {{.ColorScheme.TableHeaderBg}};{{else}}background-color: #4CAF50;{{end}}
            {{if .ColorScheme}}color: {{.ColorScheme.TableHeaderText}};{{else}}color: var(--table-header-text);{{end}}
            padding: 12px;
            text-align: left;
            font-weight: bold;
            cursor: pointer;
            user-select: none;
            position: relative;
        }
        th:hover {
            opacity: 0.9;
        }
        th.sortable::after {
            content: ' ↕';
            opacity: 0.5;
            font-size: 0.8em;
        }
        th.sort-asc::after {
            content: ' ↑';
            opacity: 1;
        }
        th.sort-desc::after {
            content: ' ↓';
            opacity: 1;
        }
        th:nth-child(2) {
            text-align: right;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
            {{if .ColorScheme}}color: {{.ColorScheme.TableOtherText}};{{else}}color: var(--table-other-text);{{end}}
        }
        td:nth-child(2) {
            text-align: right;
        }
        .hash {
            font-family: monospace;
            font-size: 0.9em;
        }
        tr:hover {
            background-color: var(--row-hover);
        }
        a {
            {{if .ColorScheme}}color: {{.ColorScheme.TableFilenameText}};{{else}}color: var(--link);{{end}}
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        tfoot {
            border-top: 2px solid var(--border-color);
        }
        tfoot td {
            font-weight: bold;
            padding: 12px;
            {{if .ColorScheme}}background-color: {{.ColorScheme.TableHeaderBg}};{{else}}background-color: var(--tfoot-bg);{{end}}
            {{if .ColorScheme}}color: {{.ColorScheme.TableHeaderText}};{{else}}color: var(--text);{{end}}
        }
        tfoot td:nth-child(2) {
            text-align: right;
        }
        .loading {
            text-align: center;
            padding: 20px;
            color: var(--muted);
        }
        .error {
            color: var(--error);
            padding: 20px;
            text-align: center;
        }
        :root {
            --bg: #f5f5f5;
            --text: #333333;
            --table-bg: #ffffff;
            --table-header-text: #ffffff;
            --table-other-text: #333333;
            --link: #2196f3;
            --tfoot-bg: #f9f9f9;
            --border-color: #dddddd;
            --row-hover: #f0f0f0;
            --muted: #666666;
            --error: #d32f2f;
        }
        body[data-theme="light"] {
            --bg: #f5f5f5;
            --text: #333333;
            --table-bg: #ffffff;
            --table-header-text: #ffffff;
            --table-other-text: #333333;
            --link: #2196f3;
            --tfoot-bg: #f9f9f9;
            --border-color: #dddddd;
            --row-hover: #f0f0f0;
            --muted: #666666;
            --error: #ff6b6b;
        }
        body[data-theme="dark"] {
            --bg: #121212;
            --text: #f1f1f1;
            --table-bg: #1b1b1b;
            --table-header-text: #ffffff;
            --table-other-text: #e0e0e0;
            --link: #7cc4ff;
            --tfoot-bg: #242424;
            --border-color: #3a3a3a;
            --row-hover: #2a2a2a;
            --muted: #b0b0b0;
            --error: #ff8a80;
        }
        .theme-toggle {
            margin-left: 12px;
            padding: 6px 12px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--table-bg);
            color: var(--text);
            cursor: pointer;
            font-family: monospace;
            font-size: 0.95em;
        }
        .theme-toggle:hover {
            background: var(--row-hover);
        }
        .file-actions {
            display: inline-flex;
            gap: 8px;
            margin-right: 8px;
            vertical-align: middle;
        }
        .action-icon {
            font-size: 0.95em;
            text-decoration: none;
            cursor: pointer;
            opacity: 0.9;
            border: 1px solid var(--border-color);
            border-radius: 3px;
            padding: 0 4px;
            line-height: 1.3;
            color: var(--link);
            background: transparent;
        }
        .action-icon:hover {
            opacity: 1;
            text-decoration: none;
            background: var(--row-hover);
        }
    </style>
</head>
<body>
    <h1>Files</h1>
    <div style="margin-bottom: 14px;">
        <input id="searchInput" type="search" autocomplete="off" placeholder="Search in this folder…" style="width: 100%; max-width: 42rem; box-sizing: border-box; padding: 8px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--table-bg); color: var(--text); font-family: monospace;">
    </div>
    <div id="loading" class="loading">Loading...</div>
    <div id="error" class="error" style="display: none;"></div>
    <table id="fileTable" style="display: none;">
        <thead>
            <tr>
                <th class="sortable" data-sort="name" data-sort-type="string">Name</th>
                <th class="sortable" data-sort="size" data-sort-type="number">Size</th>
                <th id="hashHeader" class="sortable" data-sort="hash" data-sort-type="string" style="display: none;">SHA1</th>
                <th class="sortable" data-sort="modified" data-sort-type="number">Modified</th>
            </tr>
        </thead>
        <tbody id="fileTableBody">
        </tbody>
        <tfoot id="fileTableFooter">
        </tfoot>
    </table>
    <script>
        (function() {
            const tableBody = document.getElementById('fileTableBody');
            const tableFooter = document.getElementById('fileTableFooter');
            const table = document.getElementById('fileTable');
            const loading = document.getElementById('loading');
            const errorDiv = document.getElementById('error');
            const hashHeader = document.getElementById('hashHeader');
            const searchInput = document.getElementById('searchInput');
            let currentFiles = [];
            let currentSort = { column: null, direction: 'asc' };
            let showHash = false;
            const publicBase = {{if .PublicBaseURL}}{{printf "%q" .PublicBaseURL}}{{else}}""{{end}};
            let activeSearchQuery = '';
            let searchDebounceTimer = null;
            let pendingSearchAbort = null;
            const searchDebounceMs = 250;
            const hasCustomTheme = {{if .UseDefaultTheme}}false{{else}}true{{end}};
            
            // Get current path from URL
            function getCurrentPath() {
                const path = window.location.pathname;
                return path === '/' ? '' : decodeURIComponent(path.substring(1));
            }

            // Encode a path for use in URLs while preserving directory separators
            function encodePath(path) {
                return path.split('/').map(encodeURIComponent).join('/');
            }

            function joinPath(base, child) {
                if (!base) return child;
                return base.replace(/\/+$/, '') + '/' + child;
            }

            function getParentPath(path) {
                if (!path) return '';
                const idx = path.lastIndexOf('/');
                return idx === -1 ? '' : path.substring(0, idx);
            }

            function isMediaFile(filename) {
                const ext = filename.toLowerCase().split('.').pop();
                const mediaExtensions = new Set([
                    'mp4', 'mkv', 'webm', 'avi', 'mov', 'm4v', 'wmv', 'flv',
                    'mp3', 'wav', 'ogg', 'oga', 'aac', 'm4a', 'flac', 'opus'
                ]);
                return mediaExtensions.has(ext);
            }

            function isPreviewableFile(filename) {
                const ext = filename.toLowerCase().split('.').pop();
                const previewExtensions = new Set([
                    'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp', 'ico',
                    'pdf',
                    'txt', 'md', 'markdown', 'rst', 'log',
                    'json', 'xml', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf',
                    'html', 'htm', 'css', 'js', 'c', 'h', 'go', 'rs', 'py', 'sh', 'java', 'ts', 'tsx', 'jsx'
                ]);
                return previewExtensions.has(ext);
            }

            function showStreamUrl(url) {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(url).then(function() {
                        errorDiv.style.display = 'block';
                        errorDiv.textContent = 'Stream URL copied. Paste into VLC/mpv: ' + url;
                    }).catch(function() {
                        errorDiv.style.display = 'block';
                        errorDiv.textContent = 'Stream URL: ' + url;
                    });
                } else {
                    errorDiv.style.display = 'block';
                    errorDiv.textContent = 'Stream URL: ' + url;
                }
            }

            function abortPendingSearch() {
                if (pendingSearchAbort) {
                    pendingSearchAbort.abort();
                    pendingSearchAbort = null;
                }
            }

            function launchExternalPlayer(streamUrl, m3uUrl) {
                errorDiv.style.display = 'none';
                errorDiv.textContent = '';

                // Try protocol handler first (works when vlc:// is registered).
                const launchLink = document.createElement('a');
                launchLink.href = 'vlc://' + streamUrl;
                launchLink.style.display = 'none';
                document.body.appendChild(launchLink);
                launchLink.click();
                document.body.removeChild(launchLink);

                // If app launch works, page usually loses focus/visibility.
                let appLaunchDetected = false;
                const markLaunched = function() { appLaunchDetected = true; };
                window.addEventListener('blur', markLaunched, { once: true });
                document.addEventListener('visibilitychange', function onVisibilityChange() {
                    if (document.visibilityState === 'hidden') {
                        appLaunchDetected = true;
                    }
                    if (document.visibilityState === 'visible') {
                        document.removeEventListener('visibilitychange', onVisibilityChange);
                    }
                });

                // Fallback: copy direct URL and trigger M3U download/open.
                window.setTimeout(function() {
                    if (appLaunchDetected) {
                        return;
                    }
                    showStreamUrl(streamUrl);
                    const m3uLink = document.createElement('a');
                    m3uLink.href = m3uUrl;
                    m3uLink.style.display = 'none';
                    document.body.appendChild(m3uLink);
                    m3uLink.click();
                    document.body.removeChild(m3uLink);
                }, 1200);
            }

            // Format file size
            function formatSize(size) {
                const unit = 1024;
                if (size < unit) return size + ' B';
                let div = unit, exp = 0;
                for (let n = size / unit; n >= unit; n /= unit) {
                    div *= unit;
                    exp++;
                }
                return (size / div).toFixed(1) + ' ' + 'KMGTPE'[exp] + 'B';
            }
            
            // Format date from ISO string
            function formatDate(dateStr) {
                const date = new Date(dateStr);
                if (isNaN(date.getTime())) {
                    return dateStr; // Return as-is if invalid
                }
                const year = date.getFullYear();
                const month = String(date.getMonth() + 1).padStart(2, '0');
                const day = String(date.getDate()).padStart(2, '0');
                const hours = String(date.getHours()).padStart(2, '0');
                const minutes = String(date.getMinutes()).padStart(2, '0');
                const seconds = String(date.getSeconds()).padStart(2, '0');
                return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
            }
            
            // Fetch files from API
            async function fetchFiles(path) {
                try {
                    abortPendingSearch();
                    loading.style.display = 'block';
                    errorDiv.style.display = 'none';
                    table.style.display = 'none';
                    
                    const url = path ? '/api/files?path=' + encodeURIComponent(path) : '/api/files';
                    const response = await fetch(url);
                    
                    if (!response.ok) {
                        throw new Error('Failed to fetch files');
                    }
                    
                    const data = await response.json();
                    currentFiles = data.files || [];
                    showHash = data.showHash || false;
                    
                    // Show/hide hash column
                    hashHeader.style.display = showHash ? '' : 'none';
                    
                    renderTable(data);
                    loading.style.display = 'none';
                    table.style.display = '';
                } catch (err) {
                    loading.style.display = 'none';
                    errorDiv.style.display = 'block';
                    errorDiv.textContent = 'Error loading files: ' + err.message;
                }
            }

            async function searchFiles(path, query) {
                abortPendingSearch();
                pendingSearchAbort = new AbortController();
                const mySearchCtrl = pendingSearchAbort;
                const signal = mySearchCtrl.signal;
                try {
                    loading.style.display = 'block';
                    errorDiv.style.display = 'none';
                    table.style.display = 'none';

                    const params = new URLSearchParams();
                    params.set('q', query);
                    if (path) {
                        params.set('path', path);
                    }

                    const response = await fetch('/api/search?' + params.toString(), { signal });
                    if (!response.ok) {
                        throw new Error('Failed to search files');
                    }

                    const data = await response.json();
                    currentFiles = data.files || [];
                    showHash = data.showHash || false;
                    hashHeader.style.display = showHash ? '' : 'none';

                    renderTable(data);
                    loading.style.display = 'none';
                    table.style.display = '';
                } catch (err) {
                    if (err.name === 'AbortError') {
                        return;
                    }
                    loading.style.display = 'none';
                    errorDiv.style.display = 'block';
                    errorDiv.textContent = 'Error searching files: ' + err.message;
                } finally {
                    if (pendingSearchAbort === mySearchCtrl) {
                        pendingSearchAbort = null;
                    }
                }
            }
            
            // Render table from API data
            function renderTable(data) {
                tableBody.innerHTML = '';
                const currentPath = getCurrentPath();

                // Add parent directory row when not at root.
                if (currentPath) {
                    const parentRow = document.createElement('tr');
                    const parentNameCell = document.createElement('td');
                    const parentLink = document.createElement('a');
                    const parentPath = getParentPath(currentPath);
                    const parentHref = parentPath ? '/' + encodePath(parentPath) : '/';
                    parentLink.href = parentHref;
                    parentLink.textContent = '..';
                    parentLink.addEventListener('click', function(e) {
                        e.preventDefault();
                        activeSearchQuery = '';
                        if (searchInput) searchInput.value = '';
                        if (searchDebounceTimer) {
                            clearTimeout(searchDebounceTimer);
                            searchDebounceTimer = null;
                        }
                        window.history.pushState({path: parentPath}, '', parentHref);
                        fetchFiles(parentPath);
                    });
                    parentNameCell.setAttribute('data-sort-value', '');
                    parentNameCell.appendChild(parentLink);
                    parentRow.appendChild(parentNameCell);

                    const parentSizeCell = document.createElement('td');
                    parentSizeCell.setAttribute('data-sort-value', -1);
                    parentSizeCell.textContent = '-';
                    parentSizeCell.style.textAlign = 'right';
                    parentRow.appendChild(parentSizeCell);

                    if (showHash) {
                        const parentHashCell = document.createElement('td');
                        parentHashCell.className = 'hash';
                        parentHashCell.setAttribute('data-sort-value', '');
                        parentHashCell.textContent = '-';
                        parentRow.appendChild(parentHashCell);
                    }

                    const parentModCell = document.createElement('td');
                    parentModCell.setAttribute('data-sort-value', -1);
                    parentModCell.textContent = '-';
                    parentRow.appendChild(parentModCell);
                    tableBody.appendChild(parentRow);
                }
                
                data.files.forEach(file => {
                    const row = document.createElement('tr');
                    
                    // Name column (link if not directory, otherwise navigate)
                    const nameCell = document.createElement('td');
                    const link = document.createElement('a');
                    const targetPath = joinPath(currentPath, file.displayName);
                    if (file.isDir) {
                        const encodedPath = encodePath(targetPath);
                        link.href = '/' + encodedPath;
                        link.textContent = file.prettyName ? file.prettyName : (file.displayName + '/');
                        // Prevent default navigation, fetch directory contents instead
                        link.addEventListener('click', function(e) {
                            e.preventDefault();
                            activeSearchQuery = '';
                            if (searchInput) searchInput.value = '';
                            if (searchDebounceTimer) {
                                clearTimeout(searchDebounceTimer);
                                searchDebounceTimer = null;
                            }
                            window.history.pushState({path: targetPath}, '', '/' + encodedPath);
                            fetchFiles(targetPath);
                        });
                    } else {
                        const encodedPath = encodePath(targetPath);
                        const downloadUrl = '/' + encodedPath + '?mode=download';
                        const playUrl = '/' + encodedPath + '?mode=play';
                        const previewUrl = '/' + encodedPath + '?mode=preview';
                        const m3uUrl = '/' + encodedPath + '?mode=stream';
                        const absoluteStreamUrl = (publicBase || window.location.origin) + playUrl;
                        const mediaFile = isMediaFile(file.displayName);
                        const previewFile = isPreviewableFile(file.displayName);

                        const actions = document.createElement('span');
                        actions.className = 'file-actions';

                        const downloadIcon = document.createElement('a');
                        downloadIcon.className = 'action-icon';
                        downloadIcon.href = downloadUrl;
                        downloadIcon.textContent = '⬇';
                        downloadIcon.title = 'Download';
                        actions.appendChild(downloadIcon);

                        if (previewFile) {
                            const previewIcon = document.createElement('a');
                            previewIcon.className = 'action-icon';
                            previewIcon.href = previewUrl;
                            previewIcon.target = '_blank';
                            previewIcon.rel = 'noopener noreferrer';
                            previewIcon.textContent = '👁';
                            previewIcon.title = 'Preview in browser';
                            actions.appendChild(previewIcon);
                        }

                        if (mediaFile) {
                            const playIcon = document.createElement('a');
                            playIcon.className = 'action-icon';
                            playIcon.href = playUrl;
                            playIcon.target = '_blank';
                            playIcon.rel = 'noopener noreferrer';
                            playIcon.textContent = '▶';
                            playIcon.title = 'Play in browser';
                            actions.appendChild(playIcon);

                            const streamIcon = document.createElement('a');
                            streamIcon.className = 'action-icon';
                            streamIcon.href = playUrl;
                            streamIcon.textContent = '↗';
                            streamIcon.title = 'Launch external player';
                            streamIcon.addEventListener('click', function(e) {
                                e.preventDefault();
                                launchExternalPlayer(absoluteStreamUrl, m3uUrl);
                            });
                            actions.appendChild(streamIcon);

                            const m3uIcon = document.createElement('a');
                            m3uIcon.className = 'action-icon';
                            m3uIcon.href = m3uUrl;
                            m3uIcon.textContent = '≣';
                            m3uIcon.title = 'Download M3U playlist for external player';
                            actions.appendChild(m3uIcon);
                        }

                        nameCell.appendChild(actions);
                        link.href = downloadUrl;
                        link.textContent = file.prettyName || file.displayName;
                    }
                    nameCell.setAttribute('data-sort-value', file.displayName);
                    nameCell.appendChild(link);
                    row.appendChild(nameCell);
                    
                    // Size column
                    const sizeCell = document.createElement('td');
                    sizeCell.setAttribute('data-sort-value', file.size);
                    sizeCell.textContent = formatSize(file.size);
                    sizeCell.style.textAlign = 'right';
                    row.appendChild(sizeCell);
                    
                    // Hash column (if enabled)
                    if (showHash) {
                        const hashCell = document.createElement('td');
                        hashCell.className = 'hash';
                        hashCell.setAttribute('data-sort-value', file.hash || '0');
                        hashCell.textContent = file.hash || '-';
                        row.appendChild(hashCell);
                    }
                    
                    // Modified column
                    const modCell = document.createElement('td');
                    const modDate = new Date(file.modTime);
                    modCell.setAttribute('data-sort-value', Math.floor(modDate.getTime() / 1000));
                    let modText = formatDate(file.modTime);
                    if (!file.isDir && typeof file.downloadCount === 'number') {
                        modText += ' · ' + file.downloadCount + '×';
                    }
                    modCell.textContent = modText;
                    row.appendChild(modCell);
                    
                    tableBody.appendChild(row);
                });
                
                // Update footer
                const footerRow = document.createElement('tr');
                const fileText = data.fileCount !== 1 ? 's' : '';
                const hashCell = showHash ? '<td></td>' : '';
                footerRow.innerHTML = '<td><strong>Total: ' + data.fileCount + ' file' + fileText + '</strong></td>' +
                    '<td><strong>' + formatSize(data.totalSize) + '</strong></td>' +
                    hashCell +
                    '<td></td>';
                tableFooter.innerHTML = '';
                tableFooter.appendChild(footerRow);
            }
            
            // Sort table
            function sortTable(columnIndex, sortType) {
                const rows = Array.from(tableBody.querySelectorAll('tr'));
                const isAsc = currentSort.column === columnIndex && currentSort.direction === 'asc';
                const newDirection = isAsc ? 'desc' : 'asc';
                
                rows.sort((a, b) => {
                    const aCell = a.cells[columnIndex];
                    const bCell = b.cells[columnIndex];
                    
                    if (!aCell || !bCell) return 0;
                    
                    const aValue = aCell.getAttribute('data-sort-value') || '';
                    const bValue = bCell.getAttribute('data-sort-value') || '';
                    
                    let comparison = 0;
                    
                    if (sortType === 'number') {
                        const aNum = parseFloat(aValue) || 0;
                        const bNum = parseFloat(bValue) || 0;
                        comparison = aNum - bNum;
                    } else {
                        comparison = aValue.localeCompare(bValue, undefined, { 
                            numeric: true, 
                            sensitivity: 'base',
                            caseFirst: 'false'
                        });
                    }
                    
                    return newDirection === 'asc' ? comparison : -comparison;
                });
                
                rows.forEach(row => tableBody.removeChild(row));
                rows.forEach(row => tableBody.appendChild(row));
                
                const headers = document.querySelectorAll('th.sortable');
                headers.forEach((header, idx) => {
                    header.classList.remove('sort-asc', 'sort-desc');
                    if (idx === columnIndex) {
                        header.classList.add('sort-' + newDirection);
                    }
                });
                
                currentSort = { column: columnIndex, direction: newDirection };
            }
            
            // Add click handlers to headers
            document.querySelectorAll('th.sortable').forEach((header, index) => {
                header.addEventListener('click', () => {
                    const sortType = header.getAttribute('data-sort-type');
                    sortTable(index, sortType);
                });
            });
            
            // Handle browser back/forward buttons
            window.addEventListener('popstate', function(e) {
                const path = e.state && e.state.path ? e.state.path : getCurrentPath();
                if (activeSearchQuery) {
                    searchFiles(path, activeSearchQuery);
                } else {
                    fetchFiles(path);
                }
            });

            function runSearch() {
                const q = searchInput ? searchInput.value.trim() : '';
                activeSearchQuery = q;
                const path = getCurrentPath();
                if (!q) {
                    abortPendingSearch();
                    fetchFiles(path);
                    return;
                }
                searchFiles(path, q);
            }

            function onSearchInput() {
                if (!searchInput) return;
                const raw = searchInput.value;
                if (raw.trim() === '') {
                    if (searchDebounceTimer) {
                        clearTimeout(searchDebounceTimer);
                        searchDebounceTimer = null;
                    }
                    activeSearchQuery = '';
                    abortPendingSearch();
                    fetchFiles(getCurrentPath());
                    return;
                }
                if (searchDebounceTimer) {
                    clearTimeout(searchDebounceTimer);
                }
                searchDebounceTimer = setTimeout(function() {
                    searchDebounceTimer = null;
                    runSearch();
                }, searchDebounceMs);
            }

            function clearSearch() {
                activeSearchQuery = '';
                if (searchDebounceTimer) {
                    clearTimeout(searchDebounceTimer);
                    searchDebounceTimer = null;
                }
                abortPendingSearch();
                searchInput.value = '';
                fetchFiles(getCurrentPath());
            }
            
            // Initial load
            function applyInitialTheme() {
                if (hasCustomTheme) {
                    return;
                }
                const saved = localStorage.getItem('shareplane-theme');
                let theme = saved;
                if (!theme) {
                    theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                }
                document.body.setAttribute('data-theme', theme);
            }

            function toggleTheme() {
                const current = document.body.getAttribute('data-theme') || 'light';
                const next = current === 'dark' ? 'light' : 'dark';
                document.body.setAttribute('data-theme', next);
                localStorage.setItem('shareplane-theme', next);
            }

            applyInitialTheme();

            window.addEventListener('DOMContentLoaded', function() {
                const themeToggle = document.getElementById('themeToggle');
                if (themeToggle) {
                    themeToggle.addEventListener('click', toggleTheme);
                }

                if (searchInput) {
                    searchInput.addEventListener('input', onSearchInput);
                    searchInput.addEventListener('keydown', function(e) {
                        if (e.key === 'Enter') {
                            if (searchDebounceTimer) {
                                clearTimeout(searchDebounceTimer);
                                searchDebounceTimer = null;
                            }
                            runSearch();
                        } else if (e.key === 'Escape') {
                            clearSearch();
                        }
                    });
                }
            });

            fetchFiles(getCurrentPath());
        })();
    </script>
    <div class="endpoint-links" style="margin-top: 24px; padding: 12px 16px; {{if .ColorScheme}}color: {{.ColorScheme.Text}};{{else}}color: var(--text);{{end}} border: 1px solid var(--border-color); border-radius: 4px; font-size: 0.9em; max-width: 42rem;">
        <strong>Endpoints</strong>
        <ul style="margin: 8px 0 0 0; padding-left: 1.25rem; line-height: 1.5;">
            <li><code>GET /</code> — HTML listing (this page)</li>
            <li><a href="/api/files">/api/files</a> — JSON (<code>?path=relative/dir</code> optional)</li>
            <li><a href="/api/search?q=">/api/search</a> — search (<code>q</code> required; <code>path</code> scopes to folder)</li>
            <li><a href="/verify?file=">/verify</a> — JSON SHA1 for a file (<code>file</code> or <code>path</code>)</li>
            <li><a href="/api/downloads">/api/downloads</a> — JSON: per-client IP, full vs partial fetches per file</li>
            <li><a href="/api/status">/api/status</a> — JSON: version, totals, per-file and per-client stats</li>
            <li><code>GET /…?mode=preview</code> — inline preview (images, PDF, text, etc.) in the browser</li>
        </ul>
    </div>
    <footer style="margin-top: 30px; padding: 20px; text-align: center; {{if .ColorScheme}}color: {{.ColorScheme.Text}};{{else}}color: var(--muted);{{end}} border-top: 1px solid var(--border-color);">
        <p style="margin: 0;">
            shareplane Version {{.Version}} -
            <a href="https://github.com/network-plane/shareplane" target="_blank" style="text-decoration: none; display: inline-block; vertical-align: middle; margin-left: 8px;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="{{if .ColorScheme}}{{.ColorScheme.TableFilenameText}}{{else}}#2196F3{{end}}" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
            </a>
            {{if .UseDefaultTheme}}
            <button id="themeToggle" class="theme-toggle" type="button" aria-label="Toggle light and dark theme">
                Toggle Theme
            </button>
            {{end}}
        </p>
    </footer>
</body>
</html>
    `))
	
	data := templateData{
		ShowHash:        showHash,
		ColorScheme:     colorScheme,
		UseDefaultTheme: colorScheme == nil,
		Version:         version,
		PublicBaseURL:   serverPublicBaseURL,
	}
	if err := tmpl.Execute(cw, data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
		return
	}
	
	totalBytesSentForListings += cw.bytesWritten
}
