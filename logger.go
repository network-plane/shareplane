package main

import (
	"fmt"
	"io"
	"os"
)

var (
	serverLogFile *os.File
	serverOut     io.Writer = os.Stdout
)

func initServerLog(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	serverLogFile = f
	serverOut = io.MultiWriter(os.Stdout, f)
	return nil
}

func closeServerLog() {
	if serverLogFile != nil {
		_ = serverLogFile.Close()
		serverLogFile = nil
		serverOut = os.Stdout
	}
}

// tuiServerOutput avoids corrupting the TUI: silence stdout, or log to file only when --log is set.
func tuiServerOutput(logPath string) {
	if logPath == "" {
		serverOut = io.Discard
		return
	}
	if serverLogFile != nil {
		serverOut = serverLogFile
	}
}

func outPrintf(format string, a ...interface{}) {
	fmt.Fprintf(serverOut, format, a...)
}

func outPrintln(a ...interface{}) {
	fmt.Fprintln(serverOut, a...)
}
