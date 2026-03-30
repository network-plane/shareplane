package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/pbkdf2"
)

const (
	encryptMagic       = "SPZ1"
	maxEncryptFileSize = 64 << 20 // 64 MiB
)

// serveEncryptedZstd writes a .spz payload: magic + salt + nonce + AES-GCM(zstd(file bytes)).
// w may be a countingWriter; ResponseWriter methods are used for HEAD and headers.
func serveEncryptedZstd(w http.ResponseWriter, r *http.Request, validatedPath string, password string) error {
	if r.Header.Get("Range") != "" {
		http.Error(w, "Range requests are not supported for encrypted downloads", http.StatusRequestedRangeNotSatisfiable)
		return fmt.Errorf("range")
	}
	data, err := os.ReadFile(validatedPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return err
	}
	if len(data) > maxEncryptFileSize {
		http.Error(w, "File too large for --encrypt mode (max 64 MiB)", http.StatusRequestEntityTooLarge)
		return fmt.Errorf("too large")
	}

	var zbuf bytes.Buffer
	zw, err := zstd.NewWriter(&zbuf, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		http.Error(w, "Compression error", http.StatusInternalServerError)
		return err
	}
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		http.Error(w, "Compression error", http.StatusInternalServerError)
		return err
	}
	if err := zw.Close(); err != nil {
		http.Error(w, "Compression error", http.StatusInternalServerError)
		return err
	}
	compressed := zbuf.Bytes()

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	sealed := gcm.Seal(nil, nonce, compressed, nil)

	base := filepath.Base(validatedPath)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", base+".spz"))

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encryptMagic)+len(salt)+len(nonce)+len(sealed)))
		w.WriteHeader(http.StatusOK)
		return nil
	}

	_, _ = io.WriteString(w, encryptMagic)
	_, _ = w.Write(salt)
	_, _ = w.Write(nonce)
	_, _ = w.Write(sealed)
	return nil
}
