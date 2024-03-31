package main

import "fmt"

func printStats() {
	fmt.Println("Downloaded files:")
	var totalDownloadedBytes int64
	for file, stats := range downloadStats {
		fmt.Printf("%s - downloaded %d times, %d bytes\n", file, stats.Count, stats.Bytes)
		totalDownloadedBytes += stats.Bytes
	}
	fmt.Printf("Total bytes for file downloads: %d\n", totalDownloadedBytes)
	fmt.Printf("Total bytes for file listings: %d\n", totalBytesSentForListings)
}
