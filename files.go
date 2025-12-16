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
)

func serveFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path[1:] // Strip the leading slash
	cw := &countingWriter{ResponseWriter: w, path: path}

	// Determine the file size
	fileInfo, err := os.Stat(path)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	fileSize := fileInfo.Size()

	http.ServeFile(cw, r, path)
	cw.finish()

	// Check if the download was complete
	if cw.bytesWritten < fileSize {
		fmt.Printf("Warning: File %s was not fully downloaded. Sent %d bytes out of %d total bytes.\n", path, cw.bytesWritten, fileSize)
	}
}

// serveFiles sets up the HTTP server and handlers.
func serveFiles(filePaths []string, ip string, port string, showHidden bool, hash bool, maxHashSize int64) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			serveFile(w, r)
			return
		}
		filesInfo, err := listFiles(filePaths, showHidden, hash, maxHashSize)
		if err != nil {
			http.Error(w, "Failed to list files", http.StatusInternalServerError)
			return
		}
		renderFileList(w, filesInfo, hash)
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
	Files    []FileInfo
	ShowHash bool
}

// renderFileList renders the HTML page listing all files.
func renderFileList(w http.ResponseWriter, files []FileInfo, showHash bool) {
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
            background-color: #f5f5f5;
        }
        h1 {
            color: #333;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th {
            background-color: #4CAF50;
            color: white;
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
            color: #2196F3;
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
		Files:    files,
		ShowHash: showHash,
	}
	if err := tmpl.Execute(cw, data); err != nil {
		http.Error(w, "Failed to render file list", http.StatusInternalServerError)
		return
	}

	// Update bytes sent for listings
	totalBytesSentForListings += cw.bytesWritten
}
