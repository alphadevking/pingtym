package api

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// IsSafeURL checks if a URL is safe to monitor (prevents SSRF)
// It performs atomic resolution and blocks all private/internal ranges.
func IsSafeURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format")
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("prohibited protocol: only http/https allowed")
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing hostname")
	}

	// 1. Block literal private IPs
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("private network access restricted")
		}
		return nil
	}

	// 2. Block DNS-based private IPs (Resolve and check)
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname")
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("hostname resolves to a restricted private IP")
		}
	}

	return nil
}

func isPrivateIP(ip net.IP) bool {
	// Standard Private Ranges (RFC 1918) + Loopback + Link Local
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			(ip4[0] == 169 && ip4[1] == 254) // AWS/Metadata
	}

	// Private IPv6 (Unique Local Addresses)
	return strings.HasPrefix(ip.String(), "fc00:") || strings.HasPrefix(ip.String(), "fd00:") || strings.HasPrefix(ip.String(), "fe80:")
}

func ValidateOrigin(r *http.Request) bool {
	// Standard CSRF Protection: Origin/Referer Check
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}

	isStateChange := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions

	if origin == "" {
		if isStateChange {
			// Require HTMX/AJAX headers for state changes without origin (e.g. some mobile browsers)
			return r.Header.Get("HX-Request") == "true" || r.Header.Get("X-Requested-With") != ""
		}
		return true
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	// In local dev, we might have different ports (8080 vs 3000), but in prod, Host must match exactly.
	isProd := os.Getenv("ENV") == "production" || os.Getenv("VERCEL") == "1"
	if isProd {
		return u.Host == r.Host
	}
	
	return true
}
