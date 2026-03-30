package main

import (
	"net"
	"net/http"
	"strings"
)

func ipInList(ip string, list []string) bool {
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed != nil && ipNet.Contains(parsed) {
				return true
			}
			continue
		}
		if entry == ip {
			return true
		}
	}
	return false
}

func ipAllowMiddleware(next http.HandlerFunc, getRealIP func(*http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(serverCfg.WhitelistIPs) > 0 {
			ip := getRealIP(r)
			if !ipInList(ip, serverCfg.WhitelistIPs) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		if len(serverCfg.BlacklistIPs) > 0 {
			ip := getRealIP(r)
			if ipInList(ip, serverCfg.BlacklistIPs) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func basicAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serverCfg.BasicUser == "" && serverCfg.BasicPass == "" {
			next(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="shareplane"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if serverCfg.BasicUser != "" && u != serverCfg.BasicUser {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if serverCfg.BasicPass != "" && p != serverCfg.BasicPass {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// wrapHandler applies IP allow/deny, rate limit, and basic auth (in that order).
func wrapHandler(handler http.HandlerFunc) http.HandlerFunc {
	return ipAllowMiddleware(
		rateLimitMiddleware(
			basicAuthMiddleware(handler),
			getRealIP),
		getRealIP)
}
