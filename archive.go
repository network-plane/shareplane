package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

func handleArchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !serverCfg.EnableSingleStream {
		http.NotFound(w, r)
		return
	}
	fmtName := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if fmtName != "zstd" && fmtName != "tar.gz" && fmtName != "tgz" {
		http.Error(w, "Missing or invalid format=zstd or format=tar.gz", http.StatusBadRequest)
		return
	}
	paths := r.URL.Query()["paths"]
	if len(paths) == 0 {
		http.Error(w, "Missing paths query parameter (repeat paths= for each file)", http.StatusBadRequest)
		return
	}

	var files []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		validated, ok := isPathAllowed(p)
		if !ok {
			http.Error(w, "Path not allowed: "+p, http.StatusForbidden)
			return
		}
		info, err := os.Stat(validated)
		if err != nil || info.IsDir() {
			http.Error(w, "Not a file: "+p, http.StatusBadRequest)
			return
		}
		files = append(files, validated)
	}
	if len(files) == 0 {
		http.Error(w, "No valid files to archive", http.StatusBadRequest)
		return
	}

	disposition := "attachment; filename=\"archive.tar.zst\""
	if fmtName == "zstd" {
		w.Header().Set("Content-Type", "application/zstd")
		disposition = "attachment; filename=\"archive.zstd\""
	} else {
		w.Header().Set("Content-Type", "application/gzip")
		disposition = "attachment; filename=\"archive.tar.gz\""
	}
	w.Header().Set("Content-Disposition", disposition)

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch fmtName {
	case "zstd":
		zw, err := zstd.NewWriter(w)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		tw := tar.NewWriter(zw)
		if err := writeTarFiles(tw, files); err != nil {
			_ = tw.Close()
			_ = zw.Close()
			return
		}
		if err := tw.Close(); err != nil {
			_ = zw.Close()
			return
		}
		_ = zw.Close()
	case "tar.gz", "tgz":
		gw := gzip.NewWriter(w)
		tw := tar.NewWriter(gw)
		if err := writeTarFiles(tw, files); err != nil {
			_ = tw.Close()
			_ = gw.Close()
			return
		}
		if err := tw.Close(); err != nil {
			_ = gw.Close()
			return
		}
		_ = gw.Close()
	}
}

func writeTarFiles(tw *tar.Writer, absFiles []string) error {
	for _, abs := range absFiles {
		info, err := os.Stat(abs)
		if err != nil {
			return err
		}
		rel := normalizeStatsPath(getRelativePath(abs, allowedPaths))
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		hdr.Size = info.Size()
		hdr.Mode = int64(info.Mode() & 0777)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(abs)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
