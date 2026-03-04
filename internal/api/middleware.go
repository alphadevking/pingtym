package api

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ips   = make(map[string]*visitor)
	mu    sync.Mutex
)

type visitor struct {
	lastSeen time.Time
	tokens   float64
}

// getRealIP extracts the user IP even behind a proxy (Vercel/Cloudflare/Envoy/Istio)
func getRealIP(r *http.Request) string {
	// 1. Check X-Forwarded-For (Standard for most proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Take the first IP in the list, which is the original client
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}

	// 2. Check X-Real-IP (Often used by Nginx/Envoy/Istio)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 3. Check Vercel specific header
	if vcip := r.Header.Get("x-vercel-proxied-for"); vcip != "" {
		parts := strings.Split(vcip, ",")
		return strings.TrimSpace(parts[0])
	}

	// 4. Fallback to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// RateLimitMiddleware restricts requests based on IP address
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getRealIP(r)

		mu.Lock()
		v, exists := ips[ip]
		if !exists {
			v = &visitor{lastSeen: time.Now(), tokens: 5} // Initial burst
			ips[ip] = v
		}

		// Refill tokens: 1 token per second
		now := time.Now()
		v.tokens += now.Sub(v.lastSeen).Seconds() * 1.0
		if v.tokens > 10 { // Max capacity
			v.tokens = 10
		}
		v.lastSeen = now

		if v.tokens < 1 {
			mu.Unlock()
			slog.Warn("Rate limit exceeded", "ip", ip, "path", r.URL.Path)
			http.Error(w, "Too many requests. Please slow down.", http.StatusTooManyRequests)
			return
		}

		v.tokens--
		mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// CleanupVisitors removes old rate limit entries to prevent memory leak
func init() {
	go func() {
		for {
			time.Sleep(time.Minute)
			mu.Lock()
			for ip, v := range ips {
				if time.Since(v.lastSeen) > 10*time.Minute {
					delete(ips, ip)
				}
			}
			mu.Unlock()
		}
	}()
}

// Middleware defines a function that wraps an http.Handler
type Middleware func(http.Handler) http.Handler

// Chain wraps an http.Handler with multiple middlewares
func Chain(h http.Handler, middlewares ...Middleware) http.Handler {
	for _, m := range middlewares {
		h = m(h)
	}
	return h
}

// LoggingMiddleware logs the details of every request with real IP
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		realIP := getRealIP(r)
		next.ServeHTTP(w, r)
		slog.Info("Request handled",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start),
			"ip", realIP,
		)
	})
}

// SecurityMiddleware adds essential security headers
func SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		isProd := os.Getenv("VERCEL") == "1" || os.Getenv("ENV") == "production"
		if isProd {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// Hardened Content Security Policy
		// script-src: 'self' unpkg.com (for HTMX/Alpine)
		// style-src: 'self' rsms.me (for Inter font)
		// We still allow 'unsafe-inline' for simple style/script attributes commonly used in quick UI logic,
		// but we remove it for production if possible. Here we'll keep it for HTMX compatibility but log it.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' unpkg.com 'unsafe-inline'; style-src 'self' rsms.me 'unsafe-inline'; font-src rsms.me; img-src 'self' data:; frame-ancestors 'none'; object-src 'none';")
		next.ServeHTTP(w, r)
	})
}
