package main

import (
	"fmt"
	"time"
)

// Write method for countingWriter to track the number of bytes written
func (w *countingWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.bytesWritten += int64(n)
	return n, err
}

// Called after serving a file to update global stats and print download progress
func (w *countingWriter) finish() {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	stats := downloadStats[w.path]
	stats.Bytes += w.bytesWritten
	stats.Count++
	downloadStats[w.path] = stats

	fmt.Printf("Served file %s, sent %d bytes\n", w.path, w.bytesWritten)
}

// Write method for rateLimitedWriter that throttles writes based on bandwidth limit
func (w *rateLimitedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	dataLen := int64(len(data))
	if dataLen == 0 {
		return w.ResponseWriter.Write(data)
	}

	now := time.Now()
	elapsed := now.Sub(w.lastWrite).Seconds()

	// Reset counter if more than 1 second has passed
	if elapsed >= 1.0 {
		w.bytesWritten = 0
		w.lastWrite = now
		elapsed = 0
	}

	// Calculate how long to wait if we've exceeded the limit
	if w.bytesWritten >= w.bytesPerSecond {
		waitTime := time.Duration((1.0 - elapsed) * float64(time.Second))
		if waitTime > 0 {
			time.Sleep(waitTime)
			w.bytesWritten = 0
			w.lastWrite = time.Now()
		}
	}

	// Write data in chunks to respect the bandwidth limit
	totalWritten := 0
	chunkSize := int64(8192) // 8KB chunks for smoother throttling
	if chunkSize > w.bytesPerSecond {
		chunkSize = w.bytesPerSecond
	}

	for int64(totalWritten) < dataLen {
		remaining := dataLen - int64(totalWritten)
		chunk := chunkSize
		if chunk > remaining {
			chunk = remaining
		}

		// Check if we can write this chunk without exceeding the limit
		if w.bytesWritten+chunk > w.bytesPerSecond {
			// Wait until we can write more
			elapsed := time.Since(w.lastWrite).Seconds()
			if elapsed < 1.0 {
				waitTime := time.Duration((1.0 - elapsed) * float64(time.Second))
				time.Sleep(waitTime)
			}
			w.bytesWritten = 0
			w.lastWrite = time.Now()
		}

		n, err := w.ResponseWriter.Write(data[totalWritten : totalWritten+int(chunk)])
		totalWritten += n
		w.bytesWritten += int64(n)
		if err != nil {
			return totalWritten, err
		}
	}

	return totalWritten, nil
}
