package main

func printStats() {
	outPrintln("Downloaded files:")
	var totalDownloadedBytes int64
	for file, stats := range downloadStats {
		outPrintf("%s - downloaded %d times, %d bytes\n", file, stats.Count, stats.Bytes)
		totalDownloadedBytes += stats.Bytes
	}
	outPrintf("Total bytes for file downloads: %d\n", totalDownloadedBytes)
	outPrintf("Total bytes for file listings: %d\n", totalBytesSentForListings)
	printActivityLog()
}
