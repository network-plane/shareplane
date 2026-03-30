package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func runShareplaneStatus(base string) error {
	base = strings.TrimSpace(base)
	if base == "" {
		base = os.Getenv("SHAREPLANE_URL")
	}
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	base = strings.TrimSuffix(base, "/")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(base + "/api/status")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var data apiStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Printf("shareplane %s\n", data.Version)
	fmt.Printf("Total bytes for file downloads: %d\n", data.TotalDownloadBytes)
	fmt.Printf("Total bytes for file listings: %d\n", data.TotalListingBytes)
	fmt.Println("Per file:")
	for _, f := range data.Files {
		fmt.Printf("  %s — %d×, %d bytes\n", f.Path, f.Count, f.Bytes)
	}
	fmt.Println("Per client (full / partial):")
	for _, c := range data.Clients {
		fmt.Printf("  %s\n", c.IP)
		for _, f := range c.Files {
			fmt.Printf("    %s %d full, %d partial\n", f.Path, f.Full, f.Partial)
		}
	}
	return nil
}
