package main

import (
	"strings"
	"sync/atomic"
	"time"
)

// serverCfg holds optional limits and auth (set before serveFiles).
var serverCfg struct {
	TTLDeadline        time.Time // zero = no TTL shutdown
	ByteLimit          int64
	MaxDownloadPerFile int64
	WhitelistIPs       []string
	BlacklistIPs       []string
	BasicUser          string
	BasicPass          string
	EnableQR           bool
	EnableWebDAV       bool
	EncryptPassword    string
	EnableSingleStream bool
	EnableStatsPage    bool
	EphemeralTLS       bool // --https: in-memory self-signed cert (not persisted)
	TLSCertFile        string
	TLSKeyFile         string
	EnableTUI          bool
	UploadDir          string // absolute; empty disables POST /api/upload
}

// globalBytesTransferred counts bytes sent for completed file responses (finish()).
var globalBytesTransferred int64

func bytesLimitExceeded() bool {
	if serverCfg.ByteLimit <= 0 {
		return false
	}
	return atomic.LoadInt64(&globalBytesTransferred) >= serverCfg.ByteLimit
}

func parseCommaIPs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
