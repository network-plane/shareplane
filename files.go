package main

import (
	"crypto/sha1"
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

func serveFile(w http.ResponseWriter, r *http.Request, bandwidthLimit int64) {
	path := r.URL.Path[1:] // Strip the leading slash
	clientIP := getRealIP(r)

	// Apply bandwidth limiting if specified
	finalWriter := http.ResponseWriter(w)
	if bandwidthLimit > 0 {
		finalWriter = &rateLimitedWriter{
			ResponseWriter: w,
			bytesPerSecond: bandwidthLimit,
			lastWrite:      time.Now(),
		}
	}

	cw := &countingWriter{ResponseWriter: finalWriter, path: path, clientIP: clientIP}

	// Determine the file size
	fileInfo, err := os.Stat(path)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	fileSize := fileInfo.Size()

	// Check if this is a Range request (for resuming downloads or partial fetches)
	isRangeRequest := r.Header.Get("Range") != ""

	// http.ServeFile automatically handles HTTP Range requests (206 Partial Content)
	// This enables resuming downloads and partial file fetches
	http.ServeFile(cw, r, path)
	cw.finish()

	// Check if the download was complete (only warn for non-Range requests)
	// Range requests intentionally send fewer bytes, so don't warn for those
	if !isRangeRequest && cw.bytesWritten < fileSize {
		fmt.Printf("Warning: File %s was not fully downloaded. Sent %d bytes out of %d total bytes.\n", path, cw.bytesWritten, fileSize)
	}
}

// serveFiles sets up the HTTP server and handlers.
func serveFiles(filePaths []string, ip string, port string, showHidden bool, hash bool, maxHashSize int64, bandwidthLimit int64, colorScheme *colorScheme) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// Check if the requested path is a directory
			requestedPath := r.URL.Path[1:] // Strip the leading slash
			fileInfo, err := os.Stat(requestedPath)
			if err == nil && fileInfo.IsDir() {
				// It's a directory, list its contents with styled HTML
				filesInfo, err := listFilesInDir(requestedPath, showHidden, hash, maxHashSize)
				if err != nil {
					http.Error(w, "Failed to list directory", http.StatusInternalServerError)
					return
				}
				renderFileList(w, filesInfo, hash, colorScheme)
				return
			}
			// It's a file, serve it normally
			serveFile(w, r, bandwidthLimit)
			return
		}
		// Root path, list all shared files/directories
		filesInfo, err := listFiles(filePaths, showHidden, hash, maxHashSize)
		if err != nil {
			http.Error(w, "Failed to list files", http.StatusInternalServerError)
			return
		}
		renderFileList(w, filesInfo, hash, colorScheme)
	})

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

	log.Fatal(http.ListenAndServe(listenAddress, nil))
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
		return nil, fmt.Errorf("error: cannot access '%s': %w", dirPath, err)
	}
	
	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("error: '%s' is not a directory", dirPath)
	}
	
	dirFiles, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("error: cannot read directory '%s': %w", dirPath, err)
	}
	
	for _, f := range dirFiles {
		// Skip hidden files unless showHidden flag is set
		if !showHidden && isHidden(f.Name()) {
			continue
		}
		
		fileInfo, err := f.Info()
		if err != nil {
			return nil, fmt.Errorf("error: cannot get file info for '%s': %w", filepath.Join(dirPath, f.Name()), err)
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
			Name:    fullPath,
			Size:    fileSize,
			ModTime: fileInfo.ModTime(),
			Hash:    hashValue,
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
			return nil, fmt.Errorf("error: invalid glob pattern '%s': %w", pattern, err)
		}
		if len(expandedPaths) == 0 {
			return nil, fmt.Errorf("error: no files or directories found matching pattern '%s'", pattern)
		}
		for _, path := range expandedPaths {
			fileInfo, err := os.Stat(path)
			if err != nil {
				return nil, fmt.Errorf("error: cannot access '%s': %w", path, err)
			}
			if fileInfo.IsDir() {
				dirFiles, err := os.ReadDir(path)
				if err != nil {
					return nil, fmt.Errorf("error: cannot read directory '%s': %w", path, err)
				}
				for _, f := range dirFiles {
					// Skip hidden files unless showHidden flag is set
					if !showHidden && isHidden(f.Name()) {
						continue
					}
					fileInfo, err := f.Info() // Get the FileInfo for the directory entry
					if err != nil {
						return nil, fmt.Errorf("error: cannot get file info for '%s': %w", filepath.Join(path, f.Name()), err)
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
					Name:    path,
					Size:    fileSize,
					ModTime: fileInfo.ModTime(),
					Hash:    hashValue,
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
}

// renderFileList renders the HTML page listing all files.
func renderFileList(w http.ResponseWriter, files []FileInfo, showHash bool, colorScheme *colorScheme) {
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
    </style>
</head>
<body>
    <h1>Files</h1>
    <table>
        <thead>
            <tr>
                <th>Name</th>
                <th>Size</th>
                {{if .ShowHash}}<th>SHA1</th>{{end}}
                <th>Modified</th>
            </tr>
        </thead>
        <tbody>
        {{range .Files}}
            <tr>
                <td><a href="/{{.Name}}">{{.Name}}</a></td>
                <td>{{formatSize .Size}}</td>
                {{if $.ShowHash}}<td class="hash">{{if .Hash}}{{.Hash}}{{else}}-{{end}}</td>{{end}}
                <td>{{.ModTime.Format "2006-01-02 15:04:05"}}</td>
            </tr>
        {{end}}
        </tbody>
    </table>
</body>
</html>
    `))
	data := templateData{
		Files:       files,
		ShowHash:    showHash,
		ColorScheme: colorScheme,
	}
	if err := tmpl.Execute(cw, data); err != nil {
		http.Error(w, "Failed to render file list", http.StatusInternalServerError)
		return
	}

	// Update bytes sent for listings
	totalBytesSentForListings += cw.bytesWritten
}
