package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

var pendingOneTimeTokens sync.Map // string -> struct{}

func issueOneTimeToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// fall back to timestamp-based uniqueness is unacceptable; panic rare
		panic(err)
	}
	t := hex.EncodeToString(b)
	pendingOneTimeTokens.Store(t, true)
	return t
}

func tryConsumeOneTimeToken(t string) bool {
	if t == "" {
		return false
	}
	_, ok := pendingOneTimeTokens.LoadAndDelete(t)
	return ok
}
