package server

import (
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// mwLog logs each request, redacting the auth token.
func (s *Server) mwLog(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		q := r.URL.Query()
		path := r.URL.Path
		if cmd := q.Get("cmd"); cmd != "" {
			path += " cmd=" + cmd
		}
		next(w, r)
		log.Printf("%-4s %s [%s] %s", r.Method, path, time.Since(start).Truncate(time.Millisecond), clientIP(r))
	}
}

// mwAuth enforces a valid bearer token (query ?token= or Authorization header).
func (s *Server) mwAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.tokens) == 0 {
			// No tokens configured means auth is effectively open; refuse to
			// run in that state as a safety measure.
			writeErr(w, http.StatusInternalServerError, "server has no auth tokens configured")
			return
		}
		token := r.URL.Query().Get("token")
		if token == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if !s.validToken(token) {
			writeErr(w, http.StatusUnauthorized, "invalid or missing auth token")
			return
		}
		next(w, r)
	}
}

func (s *Server) validToken(token string) bool {
	if token == "" {
		return false
	}
	tb := []byte(token)
	ok := false
	for _, valid := range s.tokens {
		if subtle.ConstantTimeCompare(tb, valid) == 1 {
			ok = true
		}
	}
	return ok
}

// mwIPAllow restricts access to configured CIDRs / IPs when set.
func (s *Server) mwIPAllow(next http.HandlerFunc) http.HandlerFunc {
	allowed := s.cfg.Auth.AllowedIPs
	if len(allowed) == 0 {
		return next
	}
	var nets []*net.IPNet
	var ips []net.IP
	for _, entry := range allowed {
		if _, n, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			ips = append(ips, ip)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ipStr := clientIP(r)
		ip := net.ParseIP(ipStr)
		if ip != nil {
			for _, n := range nets {
				if n.Contains(ip) {
					next(w, r)
					return
				}
			}
			for _, allowedIP := range ips {
				if allowedIP.Equal(ip) {
					next(w, r)
					return
				}
			}
		}
		writeErr(w, http.StatusForbidden, "client IP not allowed")
	}
}

// mwRateLimit applies the sliding-window rate limiter.
func (s *Server) mwRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.Allow() {
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next(w, r)
	}
}

// rateLimiter is a simple sliding-window limiter. limit <= 0 disables it.
type rateLimiter struct {
	mu       sync.Mutex
	requests []time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{limit: limit, window: time.Minute}
}

func (rl *rateLimiter) Allow() bool {
	if rl.limit <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	valid := 0
	for _, t := range rl.requests {
		if t.After(cutoff) {
			rl.requests[valid] = t
			valid++
		}
	}
	rl.requests = rl.requests[:valid]
	if len(rl.requests) >= rl.limit {
		return false
	}
	rl.requests = append(rl.requests, now)
	return true
}
