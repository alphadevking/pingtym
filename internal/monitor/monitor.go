package monitor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"pingtym/internal/db"
	"regexp"
	"strings"
	"time"
)

type CheckResult struct {
	Up           bool
	Latency      time.Duration // This will be used as TTFB (Server Response)
	FullDuration time.Duration // This includes body download time
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
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"components"`
	Incidents []struct {
		Name            string `json:"name"`
		Status          string `json:"status"`
		Impact          string `json:"impact"`
		IncidentUpdates []struct {
			Body string `json:"body"`
		} `json:"incident_updates"`
		AffectedComponents []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"components"`
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

			if safeIP == nil && !strings.EqualFold(os.Getenv("ENV"), "development") {
				return nil, fmt.Errorf("security: all resolved IPs are restricted")
			}

			connectIP := safeIP
			if connectIP == nil {
				connectIP = ips[0] // Use first IP in development mode
			}

			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(connectIP.String(), port))
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
	return nil
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			(ip4[0] == 169 && ip4[1] == 254)
	}
	return strings.HasPrefix(ip.String(), "fc00:") || strings.HasPrefix(ip.String(), "fd00:") || strings.HasPrefix(ip.String(), "fe80:")
}

func Ping(targetURL string) CheckResult {
	var start, dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, ttfbDone time.Time
	var remoteAddr string

	trace := &httptrace.ClientTrace{
		DNSStart:     func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:      func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart: func(_, _ string) { connStart = time.Now() },
		ConnectDone:  func(_, _ string, _ error) { connDone = time.Now() },
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				remoteAddr = info.Conn.RemoteAddr().String()
			}
		},
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { tlsDone = time.Now() },
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

	// Server performance is best measured by TTFB
	ttfb := ttfbDone.Sub(start)
	if ttfbDone.IsZero() {
		ttfb = time.Since(start)
	}

	// Drain body to enable reuse, but time it separately
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	fullDuration := time.Since(start)

	server := resp.Header.Get("Server")
	if server == "" {
		server = "N/A"
	}

	isUp := resp.StatusCode >= 200 && resp.StatusCode < 300
	errMsg := ""
	if !isUp {
		errMsg = fmt.Sprintf("status code: %d", resp.StatusCode)
	}

	return CheckResult{
		Up:           isUp,
		Latency:      ttfb,         // Primary "Performance" metric
		FullDuration: fullDuration, // Metric including data transfer
		DNS:          dnsDone.Sub(dnsStart),
		Connect:      connDone.Sub(connStart),
		TLS:          tlsDone.Sub(tlsStart),
		TTFB:         ttfb,
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

type ProviderType int

const (
	ProviderUnknown ProviderType = iota
	ProviderAtlassian
	ProviderInstatus
	ProviderGCP
	ProviderUniversalRSS
	ProviderBetterStack
	ProviderStatusIO
)

type instatusIncident struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Impact   string `json:"impact"`
	Messages []struct {
		Body string `json:"body"`
	} `json:"messages"`
}

type instatusSummary struct {
	Page struct {
		Status string `json:"status"`
	} `json:"page"`
	Components []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"components"`
	ActiveIncidents []instatusIncident `json:"activeIncidents"`
	Incidents       []instatusIncident `json:"incidents"` // Recent incidents, including those in monitoring
}

func detectStatusProvider(ctx context.Context, rawURL string) (ProviderType, string, []byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ProviderUnknown, rawURL, nil, err
	}

	// Fast path based on host
	if strings.Contains(u.Host, "statuspage.io") {
		return ProviderAtlassian, rawURL, nil, nil
	}
	if strings.Contains(u.Host, "instatus.com") {
		return ProviderInstatus, rawURL, nil, nil
	}
	if strings.Contains(u.Host, "status.cloud.google.com") {
		return ProviderGCP, rawURL, nil, nil
	}
	if strings.Contains(u.Host, "status.aws.amazon.com") && strings.Contains(u.Path, "/rss/") {
		return ProviderUniversalRSS, rawURL, nil, nil
	}

	// Fetch base URL to inspect signatures
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return ProviderUnknown, rawURL, nil, err
	}
	req.Header.Set("User-Agent", "Pingtym-Bot/1.0")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return ProviderUnknown, rawURL, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ProviderUnknown, rawURL, nil, fmt.Errorf("status page base URL returned %d", resp.StatusCode)
	}

	// Read up to 1MB to scan for signatures
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return ProviderUnknown, rawURL, nil, err
	}

	bodyStr := string(bodyBytes)

	// Detect Atlassian (Also powers Status.io API schemas)
	if strings.Contains(bodyStr, "statuspage.io") ||
		strings.Contains(bodyStr, `data-react-class="StatusPage"`) ||
		strings.Contains(bodyStr, `/api/v2/summary.json`) ||
		strings.Contains(bodyStr, "status.io") {
		return ProviderAtlassian, rawURL, bodyBytes, nil
	}

	// Detect Incident.io (Linear, etc.)
	if strings.Contains(bodyStr, "incident.io") ||
		strings.Contains(bodyStr, "incident-io") {
		// Try Atlassian schema first as they often mimic it,
		// but if it fails, the system will fall back to RSS/HTML.
		return ProviderAtlassian, rawURL, bodyBytes, nil
	}

	// Detect Instatus
	if strings.Contains(bodyStr, "instatus.com") ||
		strings.Contains(bodyStr, "Instatus") {
		return ProviderInstatus, rawURL, bodyBytes, nil
	}

	// Detect BetterStack
	if strings.Contains(bodyStr, "betterstack.com") ||
		strings.Contains(bodyStr, "Better Stack") {
		return ProviderBetterStack, rawURL, bodyBytes, nil
	}

	// Detect Status.io (Gold Standard Signature)
	if strings.Contains(bodyStr, "status.io") ||
		strings.Contains(bodyStr, "statuspage-200.css") ||
		strings.Contains(bodyStr, "statusio_data") {
		return ProviderStatusIO, rawURL, bodyBytes, nil
	}

	// Check for a hidden RSS feed as a very strong signal for Universal RSS
	// First check head, then check whole body if nothing found
	if feedURL := extractFeedURL(bodyStr, rawURL); feedURL != "" {
		return ProviderUniversalRSS, feedURL, bodyBytes, nil
	}

	return ProviderUnknown, rawURL, bodyBytes, nil
}

func CheckSaaSStatus(monitorID int, statusPageURL string) ([]db.SaaSServiceStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	provider, baseURL, htmlBytes, err := detectStatusProvider(ctx, statusPageURL)
	if err != nil {
		return nil, fmt.Errorf("provider detection failed: %w", err)
	}

	var results []db.SaaSServiceStatus

	switch provider {
	case ProviderAtlassian:
		res, err := parseAtlassian(ctx, monitorID, baseURL)
		if err == nil && len(res) > 0 {
			return res, nil
		}
	case ProviderInstatus:
		res, err := parseInstatus(ctx, monitorID, baseURL)
		if err == nil && len(res) > 0 {
			return res, nil
		}
	case ProviderGCP:
		res, err := parseGCP(ctx, monitorID)
		if err == nil && len(res) > 0 {
			return res, nil
		}
	case ProviderUniversalRSS:
		res, err := parseUniversalRSS(ctx, monitorID, baseURL)
		if err == nil && len(res) > 0 {
			return res, nil
		}
	case ProviderBetterStack:
		res, err := parseBetterStack(ctx, monitorID, baseURL)
		if err == nil && len(res) > 0 {
			return res, nil
		}
	case ProviderStatusIO:
		// Status.io native pages store status in the HTML or a dedicated endpoint.
		// For now, if we detect Status.io, we prioritize hitting /api/v2/summary.json (some support it),
		// then fall back to HTML or native parsing.
		res, err := parseAtlassian(ctx, monitorID, baseURL)
		if err == nil && len(res) > 0 {
			return res, nil
		}
	}

	// Fallback to Generic HTML Parsing
	if len(htmlBytes) > 0 {
		status := "operational"

		// Clean the HTML to remove <script> and <style> tags which often contain JSON dictionaries
		// with words like "under maintenance" or "outage" that trigger false positives.
		cleanText := cleanHTMLText(string(htmlBytes))
		lowerHTML := strings.ToLower(cleanText)

		// Very basic heuristics for outages (Gold Standard Keywords)
		outageKeywords := []string{"outage", "degraded", "experiencing issues", "down", "incident", "investigating", "disruption", "degradation", "under maintenance", "delay", "intermittent", "disrupted"}
		operationalKeywords := []string{"all systems operational", "functioning normally", "no active incidents", "fully operational", "systems online", "operational"}

		outageScore := 0
		for _, kw := range outageKeywords {
			if strings.Contains(lowerHTML, kw) {
				outageScore++
			}
		}

		opScore := 0
		for _, kw := range operationalKeywords {
			if strings.Contains(lowerHTML, kw) {
				opScore++
			}
		}

		if outageScore > 0 && outageScore > opScore {
			status = "major_outage" // Fits cleanly with Statuspage conventions used in frontend
		}

		results = append(results, db.SaaSServiceStatus{
			MonitorID:   monitorID,
			ServiceName: "Main Service",
			Status:      status,
			LastChecked: time.Now(),
		})
		return results, nil
	}

	// Final absolute fallback (Generic HTTP)
	results = append(results, db.SaaSServiceStatus{
		MonitorID:   monitorID,
		ServiceName: "Main Service",
		Status:      "operational",
		LastChecked: time.Now(),
	})
	return results, nil
}

func parseAtlassian(ctx context.Context, monitorID int, baseURL string) ([]db.SaaSServiceStatus, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	cleanPath := strings.TrimRight(u.Path, "/")
	apiURL := fmt.Sprintf("%s://%s%s/api/v2/summary.json", u.Scheme, u.Host, cleanPath)

	req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	req.Header.Set("User-Agent", "Pingtym-Bot/1.0")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("atlassian API returned %d", resp.StatusCode)
	}

	var summary statusPageSummary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&summary); err != nil {
		return nil, err
	}

	// Build an index of component IDs affected by active (non-resolved) incidents.
	// Critical fix: Atlassian allows incidents to affect components whose status field
	// may still say "operational" if the page owner didn't update it manually.
	type incidentOverride struct {
		impact    string
		latestFix string
	}
	activeByComponentID := make(map[string]incidentOverride)
	for _, inc := range summary.Incidents {
		if inc.Status == "resolved" {
			continue
		}
		fix := ""
		if len(inc.IncidentUpdates) > 0 {
			fix = inc.IncidentUpdates[0].Body
		}
		for _, affected := range inc.AffectedComponents {
			activeByComponentID[affected.ID] = incidentOverride{
				impact:    inc.Impact,
				latestFix: fix,
			}
		}
	}

	var results []db.SaaSServiceStatus
	for _, comp := range summary.Components {
		if comp.Name == "" {
			continue
		}

		status := db.SaaSServiceStatus{
			MonitorID:   monitorID,
			ServiceName: comp.Name,
			Status:      comp.Status,
			LastChecked: time.Now(),
		}

		// Override status if an active incident explicitly names this component —
		// even if comp.Status is "operational" (catches lazy status page owners).
		if override, affected := activeByComponentID[comp.ID]; affected {
			if status.Status == "operational" {
				status.Status = "degraded_performance"
			}
			status.Impact = override.impact
			status.LatestFix = override.latestFix
		} else if comp.Status != "operational" {
			// Standard case: component itself correctly marked non-operational.
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

func parseInstatus(ctx context.Context, monitorID int, baseURL string) ([]db.SaaSServiceStatus, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	cleanPath := strings.TrimRight(u.Path, "/")
	apiURL := fmt.Sprintf("%s://%s%s/summary.json", u.Scheme, u.Host, cleanPath)

	req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	req.Header.Set("User-Agent", "Pingtym-Bot/1.0")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("instatus API returned %d", resp.StatusCode)
	}

	var summary instatusSummary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&summary); err != nil {
		return nil, err
	}

	// Index active incidents by component (Instatus does not always map them by ID in summary,
	// but we can check if any active incident mentions a component or is global)
	isGlobalOutage := false
	globalImpact := ""
	globalMessage := ""

	// SCAN BOTH ActiveIncidents and Incidents (in case some are in monitoring/lagging state)
	checkIncidents := func(incs []instatusIncident) {
		for _, inc := range incs {
			lowerStatus := strings.ToLower(inc.Status)
			if lowerStatus != "resolved" && lowerStatus != "completed" && lowerStatus != "" {
				isGlobalOutage = true
				globalImpact = inc.Impact
				if len(inc.Messages) > 0 {
					globalMessage = inc.Messages[0].Body
				}
				break
			}
		}
	}

	checkIncidents(summary.ActiveIncidents)
	if !isGlobalOutage {
		checkIncidents(summary.Incidents)
	}

	var results []db.SaaSServiceStatus
	for _, comp := range summary.Components {
		if comp.Name == "" {
			continue
		}
		status := db.SaaSServiceStatus{
			MonitorID:   monitorID,
			ServiceName: comp.Name,
			Status:      strings.ToLower(comp.Status),
			LastChecked: time.Now(),
		}

		// Override if global outage exists but component status is laggy
		if isGlobalOutage && (status.Status == "operational" || status.Status == "") {
			status.Status = "partial_outage"
			status.Impact = globalImpact
			status.LatestFix = globalMessage
		} else if strings.ToUpper(comp.Status) != "OPERATIONAL" && isGlobalOutage {
			status.Impact = globalImpact
			status.LatestFix = globalMessage
		}

		results = append(results, status)
	}
	return results, nil
}

type gcpIncident struct {
	ID               string `json:"id"`
	Number           string `json:"number"`
	Begin            string `json:"begin"`
	End              string `json:"end"` // Nullable/missing if active
	Severity         string `json:"severity"`
	StatusImpact     string `json:"status_impact"`
	ExternalDesc     string `json:"external_desc"`
	AffectedProducts []struct {
		Title string `json:"title"`
	} `json:"affected_products"`
}

func parseGCP(ctx context.Context, monitorID int) ([]db.SaaSServiceStatus, error) {
	apiURL := "https://status.cloud.google.com/incidents.json"
	req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	req.Header.Set("User-Agent", "Pingtym-Bot/1.0")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp API returned %d", resp.StatusCode)
	}

	var incidents []gcpIncident
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5*1024*1024)).Decode(&incidents); err != nil {
		return nil, err
	}

	activeIncidents := make([]gcpIncident, 0)
	for _, inc := range incidents {
		if inc.End == "" {
			activeIncidents = append(activeIncidents, inc)
		}
	}

	type productStatus struct {
		impact    string
		latestFix string
	}
	affectedProds := make(map[string]productStatus)
	for _, inc := range activeIncidents {
		for _, prod := range inc.AffectedProducts {
			affectedProds[prod.Title] = productStatus{
				impact:    inc.Severity,
				latestFix: inc.ExternalDesc,
			}
		}
	}

	var results []db.SaaSServiceStatus

	if len(affectedProds) == 0 {
		results = append(results, db.SaaSServiceStatus{
			MonitorID:   monitorID,
			ServiceName: "Google Cloud (All)",
			Status:      "operational",
			LastChecked: time.Now(),
		})
		return results, nil
	}

	for prodName, statusInfo := range affectedProds {
		statusStr := "major_outage"
		switch statusInfo.impact {
		case "low":
			statusStr = "degraded_performance"
		case "medium":
			statusStr = "partial_outage"
		}

		results = append(results, db.SaaSServiceStatus{
			MonitorID:   monitorID,
			ServiceName: prodName,
			Status:      statusStr,
			Impact:      statusInfo.impact,
			LatestFix:   statusInfo.latestFix,
			LastChecked: time.Now(),
		})
	}

	return results, nil
}

// Extract an RSS or Atom feed URL from an HTML document's <head> section
func extractFeedURL(bodyStr, baseURL string) string {
	lowerBody := strings.ToLower(bodyStr)

	// Quick heuristic check to avoid heavy regex if not present
	if !strings.Contains(lowerBody, "application/rss+xml") &&
		!strings.Contains(lowerBody, "application/atom+xml") &&
		!strings.Contains(lowerBody, `type="application/rss`) &&
		!strings.Contains(lowerBody, `type="application/atom`) {
		return ""
	}

	searchContext := lowerBody
	// Often feeds are linked in the head, but for "Gold Standard" we scan the whole body if needed
	headEnd := strings.Index(lowerBody, "</head>")
	if headEnd != -1 {
		searchContext = lowerBody // Actually, let's just search the whole body to be safe
	}

	// Look for <link rel="alternate" type="application/rss+xml" href="...">
	// Find the start of potential link tags
	parts := strings.Split(searchContext, "<link")
	for _, part := range parts {
		if !strings.Contains(part, "rel=\"alternate\"") && !strings.Contains(part, "rel='alternate'") {
			continue
		}
		if !strings.Contains(part, "application/rss+xml") && !strings.Contains(part, "application/atom+xml") {
			continue
		}

		// Extract href
		hrefStartQuote := strings.IndexAny(part, `href="href='`)
		if hrefStartQuote != -1 {
			// Find actual attribute value
			startQuoteIdx := strings.IndexAny(part[hrefStartQuote:], `"'`)
			if startQuoteIdx != -1 {
				startIdx := hrefStartQuote + startQuoteIdx + 1
				endQuoteIdx := strings.IndexAny(part[startIdx:], `"'`)
				if endQuoteIdx != -1 {
					feedURL := strings.TrimSpace(part[startIdx : startIdx+endQuoteIdx])

					// Resolve relative URLs to absolute
					if strings.HasPrefix(feedURL, "/") {
						if u, err := url.Parse(baseURL); err == nil {
							return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, feedURL)
						}
					}
					// If it's a relative URL without leading slash
					if !strings.HasPrefix(feedURL, "http") {
						if u, err := url.Parse(baseURL); err == nil {
							cleanPath := strings.TrimRight(u.Path, "/")
							return fmt.Sprintf("%s://%s%s/%s", u.Scheme, u.Host, cleanPath, feedURL)
						}
					}

					return feedURL
				}
			}
		}
	}

	return ""
}

// universalRSSFeed matches standard RSS 2.0 and Atom formats
type universalRSSFeed struct {
	XMLName xml.Name
	Channel struct {
		Title string `xml:"title"`
		Items []struct {
			Title       string `xml:"title"`
			Description string `xml:"description"`
			PubDate     string `xml:"pubDate"`
		} `xml:"item"` // RSS format
		Entries []struct {
			Title   string `xml:"title"`
			Content string `xml:"content"`
			Updated string `xml:"updated"`
		} `xml:"entry"` // Atom format
	} `xml:"channel"` // RSS parent
	// Atom parent matches:
	Title   string `xml:"title"`
	Entries []struct {
		Title   string `xml:"title"`
		Content string `xml:"content"`
		Summary string `xml:"summary"`
		Updated string `xml:"updated"`
	} `xml:"entry"`
}

func parseUniversalRSS(ctx context.Context, monitorID int, feedURL string) ([]db.SaaSServiceStatus, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", feedURL, nil)
	req.Header.Set("User-Agent", "Pingtym-Bot/1.0")
	// RSS feeds can sometimes block default Go agents or lack headers
	req.Header.Set("Accept", "application/rss+xml, application/rdf+xml, application/atom+xml, application/xml, text/xml")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RSS feed API returned %d", resp.StatusCode)
	}

	var feed universalRSSFeed
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 5*1024*1024)).Decode(&feed); err != nil {
		return nil, err
	}

	title := feed.Channel.Title
	if title == "" {
		title = feed.Title
	}
	if title == "" {
		title = "External Service (RSS)"
	}
	title = strings.TrimSuffix(title, " Service Status")

	status := "operational"
	impact := ""
	latestFix := ""

	// "Gold Standard" Scan: Iterate through all items/entries to find the worst active status.
	// This prevents regional outages (like AWS UAE) from being missed if they aren't the very latest entry.
	worstStatus := 0 // 0: operational, 1: partial_outage, 2: major_outage
	statusMap := map[int]string{0: "operational", 1: "partial_outage", 2: "major_outage"}

	processEntry := func(entryTitle, entryDesc string) {
		lowerTitle := strings.ToLower(entryTitle)
		lowerDesc := strings.ToLower(entryDesc)
		combined := lowerTitle + " " + lowerDesc

		// Terminology indicating an active disruption
		isDisruption := strings.Contains(combined, "outage") ||
			strings.Contains(combined, "degraded") ||
			strings.Contains(combined, "error") ||
			strings.Contains(combined, "incident") ||
			strings.Contains(combined, "investigating") ||
			strings.Contains(combined, "disruption") ||
			strings.Contains(combined, "issue")

		// Terminology indicating resolution
		isResolved := strings.Contains(lowerTitle, "resolved") ||
			strings.Contains(lowerTitle, "completed") ||
			strings.Contains(lowerTitle, "operational") ||
			strings.Contains(lowerTitle, "recovered")

		if isDisruption && !isResolved {
			currentRank := 1 // Partial
			if strings.Contains(combined, "major") || strings.Contains(combined, "critical") || strings.Contains(combined, "total") {
				currentRank = 2 // Major
			}

			if currentRank > worstStatus {
				worstStatus = currentRank
				impact = entryTitle
				latestFix = StripHTMLTags(entryDesc)
			}
		}
	}

	// Scan RSS items
	for _, itm := range feed.Channel.Items {
		processEntry(itm.Title, itm.Description)
	}
	// Scan Channel-level Atom entries
	for _, ent := range feed.Channel.Entries {
		processEntry(ent.Title, ent.Content)
	}
	// Scan Top-level Atom entries
	for _, ent := range feed.Entries {
		desc := ent.Content
		if desc == "" {
			desc = ent.Summary
		}
		processEntry(ent.Title, desc)
	}

	status = statusMap[worstStatus]
	if len(latestFix) > 200 {
		latestFix = latestFix[:197] + "..."
	}

	return []db.SaaSServiceStatus{
		{
			MonitorID:   monitorID,
			ServiceName: title,
			Status:      status,
			Impact:      impact,
			LatestFix:   latestFix,
			LastChecked: time.Now(),
		},
	}, nil
}

// StripHTMLTags removes HTML tags from a string
func StripHTMLTags(str string) string {
	builder := strings.Builder{}
	inTag := false
	for _, char := range str {
		if char == '<' {
			inTag = true
			continue
		} else if char == '>' {
			inTag = false
			continue
		}
		if !inTag {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

// cleanHTMLText aggressively removes script and style blocks before stripping tags
func cleanHTMLText(htmlStr string) string {
	// Remove <script>...</script> and <style>...</style>
	scriptRe := regexp.MustCompile(`(?is)<script.*?>.*?</script>`)
	styleRe := regexp.MustCompile(`(?is)<style.*?>.*?</style>`)

	cleaned := scriptRe.ReplaceAllString(htmlStr, " ")
	cleaned = styleRe.ReplaceAllString(cleaned, " ")

	// Then strip the rest of the HTML tags
	return StripHTMLTags(cleaned)
}

type betterStackSummary struct {
	Data struct {
		Attributes struct {
			CompanyName string `json:"company_name"`
			Status      string `json:"status"` // E.g., 'UP', 'HAS_ISSUES', 'UNDER_MAINTENANCE'
		} `json:"attributes"`
	} `json:"data"`
}

func parseBetterStack(ctx context.Context, monitorID int, baseURL string) ([]db.SaaSServiceStatus, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	cleanPath := strings.TrimRight(u.Path, "/")

	// BetterStack JSON API is at /index.json
	apiURL := ""
	if strings.HasSuffix(cleanPath, ".json") {
		apiURL = baseURL
	} else {
		apiURL = fmt.Sprintf("%s://%s%s/index.json", u.Scheme, u.Host, cleanPath)
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	req.Header.Set("User-Agent", "Pingtym-Bot/1.0")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("betterstack API returned %d", resp.StatusCode)
	}

	var summary betterStackSummary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&summary); err != nil {
		return nil, err
	}

	serviceName := summary.Data.Attributes.CompanyName
	if serviceName == "" {
		serviceName = "BetterStack Service"
	}

	// Normalize status
	rawStatus := strings.ToUpper(summary.Data.Attributes.Status)
	status := "operational"

	// BetterStack: status can be 'UP', 'HAS_ISSUES', 'DOWN'
	// We only want to flag an outage if it's explicitly non-UP
	switch rawStatus {
	case "DOWN", "ERROR":
		status = "major_outage"
	case "HAS_ISSUES", "DEGRADED", "MAINTENANCE":
		status = "partial_outage"
	}

	return []db.SaaSServiceStatus{
		{
			MonitorID:   monitorID,
			ServiceName: serviceName,
			Status:      status,
			LastChecked: time.Now(),
		},
	}, nil
}
