package main

import (
	"net/http"
	"sync"
	"time"
)

type downloadStatsItem struct {
	Bytes int64
	Count int64
}

var (
	// Use a map to track downloads, with each file's path as the key
	downloadStats             = make(map[string]downloadStatsItem)
	totalBytesSentForListings int64
	statsMutex                sync.Mutex
)

// Adjust countingWriter to immediately print download progress for each file
type countingWriter struct {
	http.ResponseWriter
	bytesWritten int64  // Track the number of bytes written
	path         string // The path of the file being served
	clientIP     string // The real client IP address
}

// rateLimitedWriter wraps a ResponseWriter and limits the write speed
type rateLimitedWriter struct {
	http.ResponseWriter
	bytesPerSecond int64
	lastWrite      time.Time
	bytesWritten   int64
	mu             sync.Mutex
}

// FileInfo is a struct to hold detailed information about files.
type FileInfo struct {
	Name        string // Full absolute path (internal use only)
	DisplayName string // Relative path for display (safe to show)
	Size        int64
	ModTime     time.Time
	Hash        string // SHA1 hash (empty if not calculated)
}

// rateLimiter implements a token bucket rate limiter per IP address
type rateLimiter struct {
	requestsPerSecond float64
	burstSize         int
	clients           map[string]*clientLimiter
	mu                sync.RWMutex
	cleanupTicker     *time.Ticker
	cleanupDone       chan struct{}
}

// clientLimiter tracks rate limiting state for a single client IP
type clientLimiter struct {
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

var (
	globalRateLimiter *rateLimiter
	rateLimiterMutex  sync.Mutex
	globalFileWatcher *fileWatcher
	fileWatcherMutex  sync.Mutex
)
