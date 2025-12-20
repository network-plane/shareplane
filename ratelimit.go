package main

import (
	"net/http"
	"time"
)

// newRateLimiter creates a new rate limiter with the specified requests per second
func newRateLimiter(requestsPerSecond float64) *rateLimiter {
	if requestsPerSecond <= 0 {
		return nil
	}

	rl := &rateLimiter{
		requestsPerSecond: requestsPerSecond,
		burstSize:         int(requestsPerSecond * 2), // Allow 2 seconds worth of burst
		clients:           make(map[string]*clientLimiter),
		cleanupDone:       make(chan struct{}),
	}

	// Start cleanup goroutine to remove old entries
	rl.cleanupTicker = time.NewTicker(5 * time.Minute)
	go rl.cleanup()

	return rl
}

// cleanup removes old client entries that haven't been used in 10 minutes
func (rl *rateLimiter) cleanup() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, client := range rl.clients {
				client.mu.Lock()
				lastUpdate := client.lastUpdate
				client.mu.Unlock()
				// Remove entries that haven't been used in 10 minutes
				if now.Sub(lastUpdate) > 10*time.Minute {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.cleanupDone:
			rl.cleanupTicker.Stop()
			return
		}
	}
}

// stop stops the rate limiter cleanup goroutine
func (rl *rateLimiter) stop() {
	if rl != nil && rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
		close(rl.cleanupDone)
	}
}

// allow checks if a request from the given IP should be allowed
// Returns true if allowed, false if rate limited
func (rl *rateLimiter) allow(ip string) bool {
	if rl == nil {
		return true // No rate limiting if limiter is nil
	}

	rl.mu.Lock()
	client, exists := rl.clients[ip]
	if !exists {
		client = &clientLimiter{
			tokens:     float64(rl.burstSize),
			lastUpdate: time.Now(),
		}
		rl.clients[ip] = client
	}
	rl.mu.Unlock()

	client.mu.Lock()
	defer client.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(client.lastUpdate).Seconds()

	// Add tokens based on elapsed time
	client.tokens += elapsed * rl.requestsPerSecond
	if client.tokens > float64(rl.burstSize) {
		client.tokens = float64(rl.burstSize)
	}

	// Check if we have enough tokens
	if client.tokens >= 1.0 {
		client.tokens -= 1.0
		client.lastUpdate = now
		return true
	}

	// Rate limited
	client.lastUpdate = now
	return false
}

// rateLimitMiddleware wraps an HTTP handler with rate limiting
func rateLimitMiddleware(handler http.HandlerFunc, getRealIP func(*http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rateLimiterMutex.Lock()
		limiter := globalRateLimiter
		rateLimiterMutex.Unlock()

		if limiter != nil {
			clientIP := getRealIP(r)
			if !limiter.allow(clientIP) {
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
		}

		handler(w, r)
	}
}

