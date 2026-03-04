package monitor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"pingtym/internal/db"
	"strings"
	"time"
)

type CheckResult struct {
	Up           bool
	Latency      time.Duration
	DNS          time.Duration
	Connect      time.Duration
	TLS          time.Duration
	TTFB         time.Duration
	ErrorMessage string
	IP           string
	Server       string
	Size         int64
}

type statusPageSummary struct {
	Components []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"components"`
	Incidents []struct {
		Name           string `json:"name"`
		Status         string `json:"status"`
		Impact         string `json:"impact"`
		IncidentUpdates []struct {
			Body string `json:"body"`
		} `json:"incident_updates"`
	} `json:"incidents"`
}

var sharedClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return validateSSRF(req.URL)
	},
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// Atomic Resolve & Validate (Prevents DNS Rebinding)
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}

			var safeIP net.IP
			for _, ip := range ips {
				if !isPrivateIP(ip) {
					safeIP = ip
					break
				}
			}

			if safeIP == nil {
				return nil, fmt.Errorf("security: all resolved IPs are restricted")
			}

			// Pin the connection to the safe IP
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

func validateSSRF(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("prohibited protocol")
	}

	// Port Restriction: Only allow standard web ports
	port := u.Port()
	if port != "" && port != "80" && port != "443" {
		return fmt.Errorf("restricted port access")
	}

	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("private IP access restricted")
		}
		return nil
	}

	ips, _ := net.LookupIP(host)
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("resolves to private IP")
		}
	}
	return nil
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return strings.HasPrefix(ip.String(), "fc00:") || strings.HasPrefix(ip.String(), "fd00:")
}

func Ping(targetURL string) CheckResult {
	var start, dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, ttfbDone time.Time
	var remoteAddr string
	
	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart: func(_, _ string) { connStart = time.Now() },
		ConnectDone:  func(_, _ string, _ error) { connDone = time.Now() },
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				remoteAddr = info.Conn.RemoteAddr().String()
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { ttfbDone = time.Now() },
	}

	req, _ := http.NewRequest("GET", targetURL, nil)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	req.Header.Set("User-Agent", "Pingtym-Bot/1.0")

	start = time.Now()
	resp, err := sharedClient.Do(req)
	
	if err != nil {
		return CheckResult{
			Up:           false,
			Latency:      time.Since(start),
			ErrorMessage: err.Error(),
		}
	}
	defer resp.Body.Close()
	
	totalLatency := time.Since(start)

	server := resp.Header.Get("Server")
	if server == "" {
		server = "N/A"
	}

	isUp := resp.StatusCode >= 200 && resp.StatusCode < 300
	errMsg := ""
	if !isUp {
		errMsg = fmt.Sprintf("status code: %d", resp.StatusCode)
	}

	// Accuracy Fix: If TTFB was never hit (e.g. cached or instant error), fallback to total
	actualTTFB := ttfbDone.Sub(start)
	if ttfbDone.IsZero() {
		actualTTFB = totalLatency
	}

	return CheckResult{
		Up:           isUp,
		Latency:      totalLatency,
		DNS:          dnsDone.Sub(dnsStart),
		Connect:      connDone.Sub(connStart),
		TLS:          tlsDone.Sub(tlsStart),
		TTFB:         actualTTFB,
		IP:           remoteAddr,
		Server:       server,
		Size:         resp.ContentLength,
		ErrorMessage: errMsg,
	}
}

func CheckSSL(domain string) (time.Time, error) {
	u, err := url.Parse(domain)
	if err != nil {
		return time.Time{}, err
	}

	host := u.Host
	if host == "" {
		host = domain
	}

	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("no certificates found")
	}

	return certs[0].NotAfter, nil
}

func CheckSaaSStatus(monitorID int, statusPageURL string) ([]db.SaaSServiceStatus, error) {
	apiURL := resolveStatusPageAPI(statusPageURL)
	
	resp, err := sharedClient.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status page API returned %d", resp.StatusCode)
	}

	// Security: Limit response size to 1MB to prevent OOM (Response Bomb)
	limitedReader := io.LimitReader(resp.Body, 1024*1024)

	var summary statusPageSummary
	if err := json.NewDecoder(limitedReader).Decode(&summary); err != nil {
		return nil, err
	}

	var results []db.SaaSServiceStatus
	for _, comp := range summary.Components {
		if comp.Name == "" { continue }
		
		status := db.SaaSServiceStatus{
			MonitorID:   monitorID,
			ServiceName: comp.Name,
			Status:      comp.Status,
			LastChecked: time.Now(),
		}

		if comp.Status != "operational" {
			for _, inc := range summary.Incidents {
				if inc.Status != "resolved" {
					status.Impact = inc.Impact
					if len(inc.IncidentUpdates) > 0 {
						status.LatestFix = inc.IncidentUpdates[0].Body
					}
					break
				}
			}
		}
		results = append(results, status)
	}

	return results, nil
}

func resolveStatusPageAPI(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	
	// Standard Atlassian Statuspage
	if strings.Contains(u.Host, "statuspage.io") || strings.Contains(u.Path, "summary.json") {
		return rawURL
	}
	
	// Try appending standard path if not present
	cleanPath := strings.TrimRight(u.Path, "/")
	return fmt.Sprintf("%s://%s%s/api/v2/summary.json", u.Scheme, u.Host, cleanPath)
}
