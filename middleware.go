package main

import (
	"fmt"
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

func logBasicAuthFailure(r *http.Request, reason string, attemptedUser string) {
	ip := getRealIP(r)
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	if len(path) > 256 {
		path = path[:256] + "…"
	}
	ua := r.UserAgent()
	if len(ua) > 200 {
		ua = ua[:200] + "…"
	}
	outPrintf("[auth-failed] client_ip=%s remote_addr=%s method=%s path=%s reason=%s attempted_user=%q ua=%q\n",
		ip, r.RemoteAddr, r.Method, path, reason, attemptedUser, ua)
	appendServerEvent("auth_failed", ip, fmt.Sprintf("method=%s path=%s reason=%s attempted_user=%q remote_addr=%s",
		r.Method, path, reason, attemptedUser, r.RemoteAddr))
}

func basicAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serverCfg.BasicUser == "" && serverCfg.BasicPass == "" {
			next(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok {
			logBasicAuthFailure(r, "missing_basic_auth", "")
			w.Header().Set("WWW-Authenticate", `Basic realm="shareplane"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if serverCfg.BasicUser != "" && u != serverCfg.BasicUser {
			logBasicAuthFailure(r, "bad_username", u)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if serverCfg.BasicPass != "" && p != serverCfg.BasicPass {
			logBasicAuthFailure(r, "bad_password", u)
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
