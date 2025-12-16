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
func serveFiles(filePaths []string, ip string, port string, noHidden bool) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			serveFile(w, r)
			return
		}
		filesInfo, err := listFiles(filePaths, noHidden)
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
func listFiles(paths []string, noHidden bool) ([]FileInfo, error) {
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
					// Skip hidden files if noHidden flag is set
					if noHidden && isHidden(f.Name()) {
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
				// Skip hidden files if noHidden flag is set
				if noHidden && isHidden(path) {
					continue
				}
				filesInfo = append(filesInfo, FileInfo{Name: path, Size: fileInfo.Size(), ModTime: fileInfo.ModTime()})
			}
		}
	}
	return filesInfo, nil
}

// renderFileList renders the HTML page listing all files.
func renderFileList(w http.ResponseWriter, files []FileInfo) {
	cw := &countingWriter{ResponseWriter: w}
	tmpl := template.Must(template.New("index").Parse(`
        <h1>Files</h1>
        <ul>
        {{range .}}
            <li><a href="/{{.Name}}">{{.Name}}</a> - {{.Size}} bytes - {{.ModTime}}</li>
        {{end}}
        </ul>
    `))
	if err := tmpl.Execute(cw, files); err != nil {
		http.Error(w, "Failed to render file list", http.StatusInternalServerError)
		return
	}

	// Update bytes sent for listings
	totalBytesSentForListings += cw.bytesWritten
}
