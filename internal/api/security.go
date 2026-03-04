package api

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// IsSafeURL checks if a URL is safe to monitor (prevents SSRF)
func IsSafeURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format")
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http and https protocols are allowed")
	}

	host := u.Hostname()
	
	// Check if the host itself is an IP literal
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("access to internal/private IPs is restricted")
		}
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil // If we can't resolve, let the monitor try
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("domain resolves to a restricted private network")
		}
	}

	return nil
}

// ValidateOrigin ensures the request comes from the same host (Production CSRF protection)
func ValidateOrigin(r *http.Request) bool {
	// Standard CSRF Protection: Origin/Referer Check
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}

	// HTMX/AJAX protection: If it's a POST/DELETE/PUT, we often expect X-Requested-With or HX-Request
	isStateChange := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions

	if origin == "" {
		if isStateChange {
			// If no origin/referer, check if it's an HTMX/AJAX request
			return r.Header.Get("HX-Request") == "true" || r.Header.Get("X-Requested-With") != ""
		}
		return true
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	// Production check: Origin must match current request Host
	return u.Host == r.Host
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for private IPv4 ranges
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}

	// Check for private IPv6 (Unique Local Addresses)
	return strings.HasPrefix(ip.String(), "fc00:") || strings.HasPrefix(ip.String(), "fd00:")
}
