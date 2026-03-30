package main

import (
	"strings"
)

// normalizeURLPath cleans a URL path from the request (after leading slash removed):
// forward slashes only, rejects empty result for non-root, and rejects any ".." segment.
func normalizeURLPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, `\`, `/`)
	s = strings.Trim(s, "/")
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			return ""
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "/")
}
