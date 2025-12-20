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
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

func serveFile(w http.ResponseWriter, r *http.Request, bandwidthLimit int64, validatedPath string) {
	clientIP := getRealIP(r)
	isHEAD := r.Method == "HEAD"

	// Apply bandwidth limiting if specified (not needed for HEAD requests)
	finalWriter := http.ResponseWriter(w)
	if bandwidthLimit > 0 && !isHEAD {
		finalWriter = &rateLimitedWriter{
			ResponseWriter: w,
			bytesPerSecond: bandwidthLimit,
			lastWrite:      time.Now(),
		}
	}

	// Only wrap with countingWriter if not HEAD (HEAD requests don't send body, so no need to count)
	var cw *countingWriter
	if !isHEAD {
		// Use relative path for logging to avoid leaking full paths
		relPath := getRelativePath(validatedPath, allowedPaths)
		cw = &countingWriter{ResponseWriter: finalWriter, path: relPath, clientIP: clientIP}
		finalWriter = cw
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
func serveFiles(filePaths []string, ip string, port string, showHidden bool, hash bool, maxHashSize int64, bandwidthLimit int64, colorScheme *colorScheme, enableReload bool, idleTimeout time.Duration) {
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
			
			for {
				select {
				case <-ticker.C:
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
							defer cancel()
							server.Shutdown(ctx)
						}
						
						printStats()
						os.Exit(0)
					}
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
			
			fileInfo, err := os.Stat(validatedPath)
			if err != nil {
				http.Error(w, "Path not found", http.StatusNotFound)
				return
			}
			
			if fileInfo.IsDir() {
				filesInfo, err = listFilesInDir(validatedPath, showHidden, hash, maxHashSize)
			} else {
				// Single file
				filesInfo = []FileInfo{{
					Name:        validatedPath,
					DisplayName: getRelativePath(validatedPath, filePaths),
					Size:        fileInfo.Size(),
					ModTime:     fileInfo.ModTime(),
					IsDir:       false,
				}}
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
				displayFiles[i].DisplayName = getRelativePath(f.Name, filePaths)
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
	
	http.HandleFunc("/", rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		updateLastActivity()
		if r.URL.Path != "/" {
			// Strip the leading slash and validate path
			requestedPath := r.URL.Path[1:]
			
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
			serveFile(w, r, bandwidthLimit, validatedPath)
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
	
	// Start server
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
			DisplayName: "", // Will be set in renderFileList
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
					DisplayName: "", // Will be set in renderFileList
					Size:        fileSize,
					ModTime:     fileInfo.ModTime(),
					Hash:        hashValue,
				})
			}
		}
	}
	return filesInfo, nil
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
	Files       []FileInfo
	ShowHash    bool
	ColorScheme *colorScheme
	TotalSize   int64
	FileCount   int
	Version     string
}

// globalAppVersion stores the application version (set by main.go)
var globalAppVersion = "1.1.73"

// setAppVersion sets the application version (called from main.go)
func setAppVersion(version string) {
	globalAppVersion = version
}

// getAppVersion returns the application version
func getAppVersion() string {
	return globalAppVersion
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
            {{if .ColorScheme}}background-color: {{.ColorScheme.Background}};{{else}}background-color: #f5f5f5;{{end}}
        }
        h1 {
            {{if .ColorScheme}}color: {{.ColorScheme.Text}};{{else}}color: #333;{{end}}
        }
        table {
            border-collapse: collapse;
            width: 100%;
            {{if .ColorScheme}}background-color: {{.ColorScheme.TableBg}};{{else}}background-color: white;{{end}}
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th {
            {{if .ColorScheme}}background-color: {{.ColorScheme.TableHeaderBg}};{{else}}background-color: #4CAF50;{{end}}
            {{if .ColorScheme}}color: {{.ColorScheme.TableHeaderText}};{{else}}color: white;{{end}}
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
            border-bottom: 1px solid #ddd;
            {{if .ColorScheme}}color: {{.ColorScheme.TableOtherText}};{{end}}
        }
        td:nth-child(2) {
            text-align: right;
        }
        .hash {
            font-family: monospace;
            font-size: 0.9em;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        a {
            {{if .ColorScheme}}color: {{.ColorScheme.TableFilenameText}};{{else}}color: #2196F3;{{end}}
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        tfoot {
            border-top: 2px solid #ddd;
        }
        tfoot td {
            font-weight: bold;
            padding: 12px;
            {{if .ColorScheme}}background-color: {{.ColorScheme.TableHeaderBg}};{{else}}background-color: #f9f9f9;{{end}}
            {{if .ColorScheme}}color: {{.ColorScheme.TableHeaderText}};{{else}}color: #333;{{end}}
        }
        tfoot td:nth-child(2) {
            text-align: right;
        }
        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }
        .error {
            color: #d32f2f;
            padding: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <h1>Files</h1>
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
            let currentFiles = [];
            let currentSort = { column: null, direction: 'asc' };
            let showHash = false;
            
            // Get current path from URL
            function getCurrentPath() {
                const path = window.location.pathname;
                return path === '/' ? '' : path.substring(1);
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
            
            // Render table from API data
            function renderTable(data) {
                tableBody.innerHTML = '';
                
                data.files.forEach(file => {
                    const row = document.createElement('tr');
                    
                    // Name column (link if not directory, otherwise navigate)
                    const nameCell = document.createElement('td');
                    const link = document.createElement('a');
                    if (file.isDir) {
                        link.href = '/' + file.displayName;
                        link.textContent = file.displayName + '/';
                        // Prevent default navigation, fetch directory contents instead
                        link.addEventListener('click', function(e) {
                            e.preventDefault();
                            window.history.pushState({path: file.displayName}, '', '/' + file.displayName);
                            fetchFiles(file.displayName);
                        });
                    } else {
                        link.href = '/' + file.displayName;
                        link.textContent = file.displayName;
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
                    modCell.textContent = formatDate(file.modTime);
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
                fetchFiles(path);
            });
            
            // Initial load
            fetchFiles(getCurrentPath());
        })();
    </script>
    <footer style="margin-top: 30px; padding: 20px; text-align: center; {{if .ColorScheme}}color: {{.ColorScheme.Text}};{{else}}color: #666;{{end}} border-top: 1px solid #ddd;">
        <p style="margin: 0;">
            shareplane Version {{.Version}} -
            <a href="https://github.com/network-plane/shareplane" target="_blank" style="text-decoration: none; display: inline-block; vertical-align: middle; margin-left: 8px;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="{{if .ColorScheme}}{{.ColorScheme.TableFilenameText}}{{else}}#2196F3{{end}}" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
            </a>
        </p>
    </footer>
</body>
</html>
    `))
	
	data := templateData{
		ShowHash:    showHash,
		ColorScheme: colorScheme,
		Version:     version,
	}
	if err := tmpl.Execute(cw, data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
		return
	}
	
	totalBytesSentForListings += cw.bytesWritten
}

// renderFileList renders the HTML page listing all files (kept for backward compatibility if needed).
func renderFileList(w http.ResponseWriter, files []FileInfo, showHash bool, colorScheme *colorScheme, basePaths []string) {
	cw := &countingWriter{ResponseWriter: w}
	tmpl := template.Must(template.New("index").Funcs(template.FuncMap{
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
            {{if .ColorScheme}}background-color: {{.ColorScheme.Background}};{{else}}background-color: #f5f5f5;{{end}}
        }
        h1 {
            {{if .ColorScheme}}color: {{.ColorScheme.Text}};{{else}}color: #333;{{end}}
        }
        table {
            border-collapse: collapse;
            width: 100%;
            {{if .ColorScheme}}background-color: {{.ColorScheme.TableBg}};{{else}}background-color: white;{{end}}
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th {
            {{if .ColorScheme}}background-color: {{.ColorScheme.TableHeaderBg}};{{else}}background-color: #4CAF50;{{end}}
            {{if .ColorScheme}}color: {{.ColorScheme.TableHeaderText}};{{else}}color: white;{{end}}
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
            border-bottom: 1px solid #ddd;
            {{if .ColorScheme}}color: {{.ColorScheme.TableOtherText}};{{end}}
        }
        td:nth-child(2) {
            text-align: right;
        }
        .hash {
            font-family: monospace;
            font-size: 0.9em;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        a {
            {{if .ColorScheme}}color: {{.ColorScheme.TableFilenameText}};{{else}}color: #2196F3;{{end}}
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        tfoot {
            border-top: 2px solid #ddd;
        }
        tfoot td {
            font-weight: bold;
            padding: 12px;
            {{if .ColorScheme}}background-color: {{.ColorScheme.TableHeaderBg}};{{else}}background-color: #f9f9f9;{{end}}
            {{if .ColorScheme}}color: {{.ColorScheme.TableHeaderText}};{{else}}color: #333;{{end}}
        }
        tfoot td:nth-child(2) {
            text-align: right;
        }
    </style>
</head>
<body>
    <h1>Files</h1>
    <table>
        <thead>
            <tr>
                <th class="sortable" data-sort="name" data-sort-type="string">Name</th>
                <th class="sortable" data-sort="size" data-sort-type="number">Size</th>
                {{if .ShowHash}}<th class="sortable" data-sort="hash" data-sort-type="string">SHA1</th>{{end}}
                <th class="sortable" data-sort="modified" data-sort-type="number">Modified</th>
            </tr>
        </thead>
        <tbody id="fileTableBody">
        {{range .Files}}
            <tr>
                <td data-sort-value="{{.DisplayName}}"><a href="/{{.DisplayName}}">{{.DisplayName}}</a></td>
                <td data-sort-value="{{.Size}}">{{formatSize .Size}}</td>
                {{if $.ShowHash}}<td class="hash" data-sort-value="{{if .Hash}}{{.Hash}}{{else}}0{{end}}">{{if .Hash}}{{.Hash}}{{else}}-{{end}}</td>{{end}}
                <td data-sort-value="{{.ModTime.Unix}}">{{.ModTime.Format "2006-01-02 15:04:05"}}</td>
            </tr>
        {{end}}
        </tbody>
        <tfoot>
            <tr>
                <td><strong>Total: {{.FileCount}} file{{if ne .FileCount 1}}s{{end}}</strong></td>
                <td><strong>{{formatSize .TotalSize}}</strong></td>
                {{if .ShowHash}}<td></td>{{end}}
                <td></td>
            </tr>
        </tfoot>
    </table>
    <script>
        (function() {
            const tableBody = document.getElementById('fileTableBody');
            const headers = document.querySelectorAll('th.sortable');
            let currentSort = { column: null, direction: 'asc' };
            
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
                        // String comparison (case-insensitive, natural sort)
                        comparison = aValue.localeCompare(bValue, undefined, { 
                            numeric: true, 
                            sensitivity: 'base',
                            caseFirst: 'false'
                        });
                    }
                    
                    return newDirection === 'asc' ? comparison : -comparison;
                });
                
                // Remove all rows
                rows.forEach(row => tableBody.removeChild(row));
                
                // Add sorted rows back in new order
                rows.forEach(row => tableBody.appendChild(row));
                
                // Update header classes to show sort direction
                headers.forEach((header, idx) => {
                    header.classList.remove('sort-asc', 'sort-desc');
                    if (idx === columnIndex) {
                        header.classList.add('sort-' + newDirection);
                    }
                });
                
                currentSort = { column: columnIndex, direction: newDirection };
            }
            
            // Add click handlers to all sortable headers
            headers.forEach((header, index) => {
                header.addEventListener('click', () => {
                    const sortType = header.getAttribute('data-sort-type');
                    sortTable(index, sortType);
                });
            });
        })();
    </script>
</body>
</html>
    `))
	// Convert files to use relative paths for display
	displayFiles := make([]FileInfo, len(files))
	for i, f := range files {
		displayFiles[i] = f
		// Use relative path for display, but keep full path for internal use
		// If DisplayName is already set, use it; otherwise compute from Name
		if displayFiles[i].DisplayName == "" {
			displayFiles[i].DisplayName = getRelativePath(f.Name, basePaths)
		}
	}
	
	// Calculate totals (only count files, not directories)
	var totalSize int64
	var fileCount int
	for _, f := range displayFiles {
		fileInfo, err := os.Stat(f.Name)
		if err == nil && !fileInfo.IsDir() {
			totalSize += f.Size
			fileCount++
		}
	}
	
	data := templateData{
		Files:       displayFiles,
		ShowHash:    showHash,
		ColorScheme: colorScheme,
		TotalSize:   totalSize,
		FileCount:   fileCount,
	}
	if err := tmpl.Execute(cw, data); err != nil {
		http.Error(w, "Failed to render file list", http.StatusInternalServerError)
		return
	}

	// Update bytes sent for listings
	totalBytesSentForListings += cw.bytesWritten
}
