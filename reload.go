package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// fileWatcher monitors files and directories for changes using fsnotify
type fileWatcher struct {
	filePaths  []string
	showHidden bool
	watcher    *fsnotify.Watcher
	watchedDirs map[string]bool
	mu         sync.RWMutex
	stopChan   chan struct{}
	debounce   map[string]time.Time
	debounceMu sync.Mutex
}

// newFileWatcher creates a new file watcher
func newFileWatcher(filePaths []string, showHidden bool) (*fileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &fileWatcher{
		filePaths:   filePaths,
		showHidden:  showHidden,
		watcher:     watcher,
		watchedDirs: make(map[string]bool),
		stopChan:    make(chan struct{}),
		debounce:    make(map[string]time.Time),
	}, nil
}

// start begins monitoring files for changes
func (fw *fileWatcher) start() {
	// Watch all directories recursively
	for _, pattern := range fw.filePaths {
		expandedPaths, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, path := range expandedPaths {
			fw.watchPath(path)
		}
	}

	// Start event processing goroutine
	go fw.processEvents()
}

// watchPath recursively watches a directory and all subdirectories
// Only watches paths within allowed directories for security
func (fw *fileWatcher) watchPath(path string) {
	// SECURITY: Validate path is within allowed directories
	validatedPath, allowed := isPathAllowed(path)
	if !allowed {
		return
	}
	
	fileInfo, err := os.Stat(validatedPath)
	if err != nil {
		return
	}

	// Skip hidden files/directories unless showHidden is enabled
	if !fw.showHidden && isHidden(validatedPath) {
		return
	}

	// Watch directories
	if fileInfo.IsDir() {
		absPath := filepath.Clean(validatedPath)

		fw.mu.Lock()
		if !fw.watchedDirs[absPath] {
			err := fw.watcher.Add(absPath)
			if err == nil {
				fw.watchedDirs[absPath] = true
			}
		}
		fw.mu.Unlock()

		// Recursively watch subdirectories
		dirFiles, err := os.ReadDir(validatedPath)
		if err == nil {
			for _, f := range dirFiles {
				fullPath := filepath.Join(validatedPath, f.Name())
				if !fw.showHidden && isHidden(f.Name()) {
					continue
				}
				if f.IsDir() {
					fw.watchPath(fullPath)
				}
			}
		}
	}
}

// processEvents processes file system events
func (fw *fileWatcher) processEvents() {
	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}
			fw.handleEvent(event)
		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("[Reload] Watcher error: %v\n", err)
		case <-fw.stopChan:
			return
		}
	}
}

// handleEvent handles a file system event with debouncing
func (fw *fileWatcher) handleEvent(event fsnotify.Event) {
	// Skip hidden files unless showHidden is enabled
	if !fw.showHidden && isHidden(event.Name) {
		return
	}

	// Debounce rapid events (e.g., multiple writes to the same file)
	fw.debounceMu.Lock()
	lastEvent, exists := fw.debounce[event.Name]
	now := time.Now()
	
	// If event happened within 100ms of last event for this file, skip it
	if exists && now.Sub(lastEvent) < 100*time.Millisecond {
		fw.debounceMu.Unlock()
		return
	}
	fw.debounce[event.Name] = now
	fw.debounceMu.Unlock()

	// Process the event
	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		fw.handleCreate(event.Name)
	case event.Op&fsnotify.Remove == fsnotify.Remove:
		fw.handleRemove(event.Name)
	case event.Op&fsnotify.Write == fsnotify.Write:
		fw.handleWrite(event.Name)
	case event.Op&fsnotify.Rename == fsnotify.Rename:
		fw.handleRename(event.Name)
	}
}

// handleCreate handles file/directory creation
func (fw *fileWatcher) handleCreate(path string) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return
	}

	if fileInfo.IsDir() {
		fmt.Printf("[Reload] New directory detected: %s\n", path)
		// Watch the new directory
		fw.watchPath(path)
	} else {
		fmt.Printf("[Reload] New file detected: %s (%s)\n", path, formatSize(fileInfo.Size()))
	}
}

// handleRemove handles file/directory removal
func (fw *fileWatcher) handleRemove(path string) {
	fw.mu.Lock()
	if fw.watchedDirs[path] {
		delete(fw.watchedDirs, path)
		// Try to remove from watcher (may fail if already removed)
		fw.watcher.Remove(path)
	}
	fw.mu.Unlock()

	// Check if it was a directory or file
	// Since it's removed, we can't stat it, so we check our watched dirs
	fw.mu.RLock()
	wasDir := fw.watchedDirs[path]
	fw.mu.RUnlock()

	if wasDir {
		fmt.Printf("[Reload] Directory removed: %s\n", path)
	} else {
		fmt.Printf("[Reload] File removed: %s\n", path)
	}
}

// handleWrite handles file modification
func (fw *fileWatcher) handleWrite(path string) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return
	}

	// Only report writes for files, not directories
	if !fileInfo.IsDir() {
		fmt.Printf("[Reload] File modified: %s (%s)\n", path, formatSize(fileInfo.Size()))
	}
}

// handleRename handles file/directory rename
func (fw *fileWatcher) handleRename(path string) {
	// Rename is often followed by Create/Remove, but we'll log it anyway
	fileInfo, err := os.Stat(path)
	if err != nil {
		// File was renamed/moved away
		fmt.Printf("[Reload] File/directory renamed/moved: %s\n", path)
		return
	}

	if fileInfo.IsDir() {
		fmt.Printf("[Reload] Directory renamed/moved: %s\n", path)
	} else {
		fmt.Printf("[Reload] File renamed/moved: %s\n", path)
	}
}

// stop stops the file watcher
func (fw *fileWatcher) stop() {
	close(fw.stopChan)
	if fw.watcher != nil {
		fw.watcher.Close()
	}
}

