package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// allowedPaths stores the normalized allowed base paths
var allowedPaths []string

// initAllowedPaths initializes the list of allowed base paths
func initAllowedPaths(filePaths []string) error {
	allowedPaths = make([]string, 0, len(filePaths))
	
	for _, pattern := range filePaths {
		expandedPaths, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("invalid glob pattern: %w", err)
		}
		
		for _, path := range expandedPaths {
			absPath, err := filepath.Abs(path)
			if err != nil {
				continue
			}
			
			// Clean the path to resolve any . or .. components
			absPath = filepath.Clean(absPath)
			
			// Check if it exists
			info, err := os.Stat(absPath)
			if err != nil {
				continue
			}
			
			// If it's a file, use its directory
			if !info.IsDir() {
				absPath = filepath.Dir(absPath)
			}
			
			// Normalize to ensure consistent comparison
			absPath = filepath.Clean(absPath)
			
			// Add if not already in list
			found := false
			for _, existing := range allowedPaths {
				if absPath == existing {
					found = true
					break
				}
			}
			if !found {
				allowedPaths = append(allowedPaths, absPath)
			}
		}
	}
	
	return nil
}

// isPathAllowed checks if a requested path is within the allowed directories
// Returns the cleaned absolute path and true if allowed, or empty string and false if not
func isPathAllowed(requestedPath string) (string, bool) {
	// Clean the requested path to prevent traversal
	cleaned := filepath.Clean(requestedPath)
	
	// Check if the path is within any allowed directory
	for _, allowed := range allowedPaths {
		// Try to resolve the path relative to this allowed directory
		// First, try as absolute path
		absPath, err := filepath.Abs(cleaned)
		if err == nil {
			absPath = filepath.Clean(absPath)
			relPath, err := filepath.Rel(allowed, absPath)
			if err == nil && !strings.HasPrefix(relPath, "..") && !strings.HasPrefix(relPath, "/") {
				return absPath, true
			}
		}
		
		// Try as relative path within the allowed directory
		combinedPath := filepath.Join(allowed, cleaned)
		absPath2, err := filepath.Abs(combinedPath)
		if err != nil {
			continue
		}
		absPath2 = filepath.Clean(absPath2)
		
		// Verify it's actually within the allowed directory (prevent ../ attacks)
		relPath, err := filepath.Rel(allowed, absPath2)
		if err != nil {
			continue
		}
		
		// If relative path doesn't start with .., it's within the allowed directory
		if !strings.HasPrefix(relPath, "..") && !strings.HasPrefix(relPath, "/") {
			// Verify the file actually exists
			if _, err := os.Stat(absPath2); err == nil {
				return absPath2, true
			}
		}
	}
	
	return "", false
}

// getRelativePath returns a relative path for display purposes
func getRelativePath(fullPath string, basePaths []string) string {
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		// Fallback to just the filename
		return filepath.Base(fullPath)
	}
	
	// Try to find the shortest relative path from any base
	shortest := fullPath
	for _, base := range basePaths {
		relPath, err := filepath.Rel(base, absPath)
		if err == nil && len(relPath) < len(shortest) && !strings.HasPrefix(relPath, "..") {
			shortest = relPath
		}
	}
	
	// If we couldn't find a relative path, just return the filename
	if shortest == fullPath || strings.HasPrefix(shortest, "..") {
		return filepath.Base(fullPath)
	}
	
	return shortest
}

