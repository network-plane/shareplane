package main

import (
	"fmt"
	"html/template"
	"log"
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
func serveFiles(filePaths []string, ip string, port string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			serveFile(w, r)
			return
		}
		filesInfo, err := listFiles(filePaths)
		if err != nil {
			http.Error(w, "Failed to list files", http.StatusInternalServerError)
			return
		}
		renderFileList(w, filesInfo)
	})

	listenAddress := fmt.Sprintf("%s:%s", ip, port)
	fmt.Printf("Serving on http://%s\n", listenAddress)

	log.Fatal(http.ListenAndServe(listenAddress, nil))
}

// listFiles generates a slice of FileInfo for the given paths, including expanding glob patterns.
func listFiles(paths []string) ([]FileInfo, error) {
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
	tmpl.Execute(cw, files)

	// Update bytes sent for listings
	totalBytesSentForListings += cw.bytesWritten
}
