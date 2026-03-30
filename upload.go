package main

import (
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if serverCfg.UploadDir == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	destBase := serverCfg.UploadDir
	sub := normalizeURLPath(r.URL.Query().Get("subdir"))
	if sub != "" {
		destBase = filepath.Join(destBase, filepath.FromSlash(sub))
		abs, err := filepath.Abs(destBase)
		if err != nil {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		rel, err := filepath.Rel(serverCfg.UploadDir, abs)
		if err != nil || strings.HasPrefix(rel, "..") {
			http.Error(w, "Invalid subdir", http.StatusForbidden)
			return
		}
		if err := os.MkdirAll(abs, 0755); err != nil {
			http.Error(w, "Cannot create directory", http.StatusInternalServerError)
			return
		}
		destBase = abs
	}

	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Error(w, "Invalid multipart form", http.StatusBadRequest)
		return
	}
	if r.MultipartForm == nil {
		http.Error(w, "Missing multipart form", http.StatusBadRequest)
		return
	}
	fhs := r.MultipartForm.File["files"]
	if len(fhs) == 0 {
		http.Error(w, "Missing files field (use multipart name \"files\")", http.StatusBadRequest)
		return
	}

	saved := make([]string, 0, len(fhs))
	for _, fh := range fhs {
		name := filepath.Base(fh.Filename)
		if name == "." || name == ".." || name == "" {
			continue
		}
		dest := filepath.Join(destBase, name)
		if err := saveMultipartFile(fh, dest); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rel, _ := filepath.Rel(serverCfg.UploadDir, dest)
		saved = append(saved, filepath.ToSlash(rel))
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string][]string{"saved": saved})
}

func saveMultipartFile(fh *multipart.FileHeader, dest string) error {
	src, err := fh.Open()
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	tmp := dest + ".partial"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
