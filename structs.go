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

// clientFileStat tracks full vs partial fetches per client IP and file path (relative key).
type clientFileStat struct {
	Full    int64 `json:"full"`
	Partial int64 `json:"partial"`
}

var (
	// Use a map to track downloads, with each file's path as the key
	downloadStats             = make(map[string]downloadStatsItem)
	totalBytesSentForListings int64
	statsMutex                sync.Mutex

	// perClientFileStats maps client IP -> relative path -> full vs partial counts
	perClientFileStats = make(map[string]map[string]clientFileStat)
	perClientMu        sync.Mutex
)

// Adjust countingWriter to immediately print download progress for each file
type countingWriter struct {
	http.ResponseWriter
	bytesWritten   int64  // Track the number of bytes written
	path           string // The path of the file being served
	clientIP       string // The real client IP address
	isRangeRequest bool   // True if client sent Range header
	fileSize       int64  // Total file size (for full vs partial)
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
	Name          string    `json:"name"`                 // Full absolute path (internal use only)
	DisplayName   string    `json:"displayName"`          // Relative path for display (safe to show)
	PrettyName    string    `json:"prettyName,omitempty"` // Label with --prefix/--suffix; empty means use displayName in UI
	Size          int64     `json:"size"`                 // File size in bytes
	ModTime       time.Time `json:"modTime"`              // Modification time
	Hash          string    `json:"hash"`                 // SHA1 hash (empty if not calculated)
	IsDir         bool      `json:"isDir"`                // Whether this is a directory
	DownloadCount int64     `json:"downloadCount"`        // Times this file was served (GET body); 0 if never
}

// apiResponse represents the JSON response from /api/files
type apiResponse struct {
	Files     []FileInfo `json:"files"`
	TotalSize int64      `json:"totalSize"`
	FileCount int        `json:"fileCount"`
	ShowHash  bool       `json:"showHash"`
}

// apiDownloadsResponse is the JSON body for GET /api/downloads
type apiDownloadsResponse struct {
	Clients []apiDownloadClient `json:"clients"`
}

type apiDownloadClient struct {
	IP    string            `json:"ip"`
	Files []apiDownloadFile `json:"files"`
}

type apiDownloadFile struct {
	Path    string `json:"path"`
	Full    int64  `json:"full"`
	Partial int64  `json:"partial"`
}

// apiStatusResponse is the JSON body for GET /api/status
type apiStatusResponse struct {
	Version            string              `json:"version"`
	TotalDownloadBytes int64               `json:"totalDownloadBytes"`
	TotalListingBytes  int64               `json:"totalListingBytes"`
	Files              []apiStatusFile     `json:"files"`
	Clients            []apiDownloadClient `json:"clients"`
	Activity           []activityEvent     `json:"activity"`
}

type apiStatusFile struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
	Bytes int64  `json:"bytes"`
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

	// Idle timeout tracking
	lastActivity   time.Time
	lastActivityMu sync.RWMutex
	httpServer     *http.Server
	httpServerMu   sync.RWMutex
)
