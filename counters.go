package main

import "fmt"

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
