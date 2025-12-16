package main

import (
	"fmt"
	"html/template"
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
func serveFiles(filePaths []string, ip string, port string, showHidden bool) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			serveFile(w, r)
			return
		}
		filesInfo, err := listFiles(filePaths, showHidden)
		if err != nil {
			http.Error(w, "Failed to list files", http.StatusInternalServerError)
			return
		}
		renderFileList(w, filesInfo)
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

// listFiles generates a slice of FileInfo for the given paths, including expanding glob patterns.
func listFiles(paths []string, showHidden bool) ([]FileInfo, error) {
	var filesInfo []FileInfo
	for _, pattern := range paths {
		expandedPaths, err := filepath.Glob(pattern)
		if err != nil {
			// Handle error if the glob pattern could not be expanded
			return nil, err
		}
		for _, path := range expandedPaths {
			fileInfo, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			if fileInfo.IsDir() {
				dirFiles, err := os.ReadDir(path)
				if err != nil {
					return nil, err
				}
				for _, f := range dirFiles {
					// Skip hidden files unless showHidden flag is set
					if !showHidden && isHidden(f.Name()) {
						continue
					}
					fileInfo, err := f.Info() // Get the FileInfo for the directory entry
					if err != nil {
						return nil, err // Handle the error if unable to get FileInfo
					}
					filesInfo = append(filesInfo, FileInfo{
						Name:    filepath.Join(path, f.Name()),
						Size:    fileInfo.Size(),    // Get the size from FileInfo
						ModTime: fileInfo.ModTime(), // Get the modification time from FileInfo
					})
				}

			} else {
				// Skip hidden files unless showHidden flag is set
				if !showHidden && isHidden(path) {
					continue
				}
				filesInfo = append(filesInfo, FileInfo{Name: path, Size: fileInfo.Size(), ModTime: fileInfo.ModTime()})
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

// renderFileList renders the HTML page listing all files.
func renderFileList(w http.ResponseWriter, files []FileInfo) {
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
                <th>Modified</th>
            </tr>
        </thead>
        <tbody>
        {{range .}}
            <tr>
                <td><a href="/{{.Name}}">{{.Name}}</a></td>
                <td>{{formatSize .Size}}</td>
                <td>{{.ModTime.Format "2006-01-02 15:04:05"}}</td>
            </tr>
        {{end}}
        </tbody>
    </table>
</body>
</html>
    `))
	if err := tmpl.Execute(cw, files); err != nil {
		http.Error(w, "Failed to render file list", http.StatusInternalServerError)
		return
	}

	// Update bytes sent for listings
	totalBytesSentForListings += cw.bytesWritten
}
