package api

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"pingtym/internal/db"
	"pingtym/internal/monitor"
	"pingtym/web"
	"strconv"
	"strings"
	"sync"
	"time"
)

var registerOnce sync.Once

var startTime = time.Now()

var templates *template.Template

func loadTemplates() error {
	var err error
	templates, err = template.New("index.html").Funcs(GetTemplateFuncs()).ParseFS(web.TemplateFS, "templates/index.html", "templates/learn.html")
	if err != nil {
		return fmt.Errorf("failed to parse template from embed: %w", err)
	}
	slog.Info("Templates loaded successfully from embedded filesystem")
	return nil
}

func RegisterHandlers() {
	registerOnce.Do(func() {
		if err := loadTemplates(); err != nil {
			slog.Error("Initial template load failed", "error", err)
		}

		http.HandleFunc("/", handleIndex)
		http.HandleFunc("/learn", handleLearn)
		http.HandleFunc("/favicon.ico", handleFavicon)
		http.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, web.TemplateFS, "assets/robots.txt")
		})
		http.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, web.TemplateFS, "assets/sitemap.xml")
		})
		http.Handle("/assets/", http.FileServer(http.FS(web.TemplateFS)))
		http.HandleFunc("/add-monitor", handleAddMonitor)
		http.HandleFunc("/delete-monitor", handleDeleteMonitor)
	})
}

func GetGlobalHandler() http.Handler {
	RegisterHandlers()
	return Chain(http.DefaultServeMux, LoggingMiddleware, SecurityMiddleware, RateLimitMiddleware)
}

func handleLearn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqLog := slog.With("request_id", RequestIDFromCtx(ctx))

	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, "learn.html", nil); err != nil {
		reqLog.Error("Failed to execute learn template", "error", err)
		http.Error(w, "An internal error occurred", http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes()) //nolint:errcheck
}

type MonitorView struct {
	db.Monitor
	SaaSStatuses   []db.SaaSServiceStatus
	Uptime24h      float64
	Uptime7d       float64
	AvgLatency     int
	MaxLatency     int
	History        []int
	LatencyHistory []int
	LastResult     monitor.CheckResult
}

type SSLView struct {
	db.SSLCheck
	DaysLeft int
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	reqLog := slog.With("request_id", RequestIDFromCtx(ctx))

	isHTMX := r.Header.Get("HX-Request") == "true"
	if isHTMX {
		reqLog.Info("Dashboard polling request received", "ip", getRealIP(r))
	}

	if templates == nil {
		if err := loadTemplates(); err != nil {
			http.Error(w, "Critical Error: Templates not found.", http.StatusInternalServerError)
			return
		}
	}

	sessionID := getSessionID(w, r)
	monitors, err := db.GetMonitors(ctx, sessionID)
	if err != nil {
		reqLog.Error("Failed to fetch monitors", "sessionID", sessionID, "error", err)
		http.Error(w, "Unable to load infrastructure registry.", http.StatusInternalServerError)
		return
	}

	var monitorViews []MonitorView
	var totalUptime float64
	downCount := 0

	for _, m := range monitors {
		statuses, err := db.GetSaaSStatuses(ctx, m.ID)
		if err != nil {
			reqLog.Warn("Failed to load SaaS statuses", "monitor_id", m.ID, "error", err)
		}

		logs, err := db.GetRecentLogs(ctx, m.ID, 30)
		if err != nil {
			reqLog.Warn("Failed to load check logs", "monitor_id", m.ID, "error", err)
		}
		history := make([]int, 0, len(logs))
		latencyHistory := make([]int, 0, len(logs))
		for i := len(logs) - 1; i >= 0; i-- {
			history = append(history, logs[i].Status)
			latencyHistory = append(latencyHistory, logs[i].LatencyMs)
		}

		var lastRes monitor.CheckResult
		if len(logs) > 0 {
			last := logs[0]
			lastRes = monitor.CheckResult{
				Up:           last.Status == 1,
				Latency:      time.Duration(last.LatencyMs) * time.Millisecond,
				DNS:          time.Duration(last.DNSMs) * time.Millisecond,
				TLS:          time.Duration(last.TLSMs) * time.Millisecond,
				TTFB:         time.Duration(last.TTFBMs) * time.Millisecond,
				FullDuration: time.Duration(last.TotalMs) * time.Millisecond,
				ErrorMessage: last.ErrorMessage,
			}
		}

		for i := range statuses {
			saasLogs, err := db.GetRecentSaaSLogStatuses(ctx, m.ID, statuses[i].ServiceName, 30)
			if err != nil {
				reqLog.Warn("Failed to load SaaS log statuses", "monitor_id", m.ID, "service", statuses[i].ServiceName, "error", err)
			}
			sh := make([]string, 0, len(saasLogs))
			for j := len(saasLogs) - 1; j >= 0; j-- {
				sh = append(sh, saasLogs[j])
			}
			statuses[i].History = sh
		}

		u24h, err := db.GetUptimePercentage(ctx, m.ID, 24*time.Hour)
		if err != nil {
			reqLog.Warn("Failed to load 24h uptime", "monitor_id", m.ID, "error", err)
		}
		u7d, err := db.GetUptimePercentage(ctx, m.ID, 7*24*time.Hour)
		if err != nil {
			reqLog.Warn("Failed to load 7d uptime", "monitor_id", m.ID, "error", err)
		}
		avgLat, err := db.GetAverageLatency(ctx, m.ID, 24*time.Hour)
		if err != nil {
			reqLog.Warn("Failed to load average latency", "monitor_id", m.ID, "error", err)
		}

		maxLat := 0
		for _, v := range latencyHistory {
			if v > maxLat {
				maxLat = v
			}
		}
		if maxLat < 100 {
			maxLat = 100
		}

		if m.LastStatus.Valid && m.LastStatus.Int64 == 0 {
			downCount++
		}

		monitorViews = append(monitorViews, MonitorView{
			Monitor:        m,
			SaaSStatuses:   statuses,
			Uptime24h:      u24h,
			Uptime7d:       u7d,
			AvgLatency:     avgLat,
			MaxLatency:     maxLat,
			History:        history,
			LatencyHistory: latencyHistory,
			LastResult:     lastRes,
		})
		totalUptime += u24h
	}

	avgUptime := 0.0
	if len(monitors) > 0 {
		avgUptime = totalUptime / float64(len(monitors))
	}

	healthStatus := "Optimal"
	healthMsg := "All systems operational"
	healthColor := "var(--success)"

	if downCount > 0 {
		healthStatus = "Degraded"
		healthMsg = fmt.Sprintf("%d service(s) currently down", downCount)
		healthColor = "var(--danger)"
	}

	sslChecks, err := db.GetSSLChecks(ctx, sessionID)
	if err != nil {
		reqLog.Error("Failed to fetch SSL checks", "sessionID", sessionID, "error", err)
	}

	sslViews := []SSLView{}
	for _, s := range sslChecks {
		days := 0
		if s.ExpiryDate.Valid {
			days = int(time.Until(s.ExpiryDate.Time).Hours() / 24)
		}
		sslViews = append(sslViews, SSLView{SSLCheck: s, DaysLeft: days})
	}

	memberSince := time.Now().Format("Jan 2006")
	if len(monitors) > 0 {
		oldest := monitors[0].CreatedAt
		for _, m := range monitors {
			if m.CreatedAt.Before(oldest) {
				oldest = m.CreatedAt
			}
		}
		memberSince = oldest.Format("Jan 2006")
	}

	tier := "Standard"
	if len(monitors) > 5 {
		tier = "Enterprise"
	}

	identityPrefix := sessionID
	if len(sessionID) >= 8 {
		identityPrefix = sessionID[:8]
	}

	userInfo := struct {
		SessionID string
		Identity  string
		Since     string
		Tier      string
		IP        string
	}{
		SessionID: sessionID,
		Identity:  fmt.Sprintf("User-%s", identityPrefix),
		Since:     memberSince,
		Tier:      tier,
		IP:        getRealIP(r),
	}

	data := struct {
		Monitors     []MonitorView
		SSLChecks    []SSLView
		GlobalAvg    float64
		TotalChecks  int
		HealthStatus string
		HealthMsg    string
		HealthColor  string
		User         interface{}
	}{
		Monitors:     monitorViews,
		SSLChecks:    sslViews,
		GlobalAvg:    avgUptime,
		TotalChecks:  len(monitors),
		HealthStatus: healthStatus,
		HealthMsg:    healthMsg,
		HealthColor:  healthColor,
		User:         userInfo,
	}

	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, "index.html", data); err != nil {
		reqLog.Error("Failed to execute template", "error", err)
		http.Error(w, "An internal error occurred", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Write(buf.Bytes()) //nolint:errcheck
}

func handleAddMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !ValidateOrigin(r) {
		http.Error(w, "Security Violation: Untrusted origin", http.StatusForbidden)
		return
	}

	ctx := r.Context()
	reqLog := slog.With("request_id", RequestIDFromCtx(ctx))

	sessionID := getSessionID(w, r)
	existing, err := db.GetMonitors(ctx, sessionID)
	if err != nil {
		reqLog.Error("Database error checking monitor quota", "sessionID", sessionID, "error", err)
		http.Error(w, "System Temporarily Unavailable: Registry connection failure.", http.StatusServiceUnavailable)
		return
	}

	if len(existing) >= 10 {
		http.Error(w, "Quota Exceeded: Max 10 monitors allowed.", http.StatusForbidden)
		return
	}

	name := r.FormValue("name")
	rawURL := strings.TrimSpace(r.FormValue("url"))
	normURL := strings.TrimRight(strings.ToLower(rawURL), "/")

	for _, m := range existing {
		if strings.TrimRight(strings.ToLower(m.URL), "/") == normURL {
			http.Error(w, "Conflict: This URL is already in your registry.", http.StatusConflict)
			return
		}
	}

	if name == "" || rawURL == "" {
		http.Error(w, "Name and URL are required", http.StatusBadRequest)
		return
	}

	if err := IsSafeURL(rawURL); err != nil {
		http.Error(w, fmt.Sprintf("Security Restriction: %v", err), http.StatusForbidden)
		return
	}

	statusPageURL := r.FormValue("status_page_url")
	webhookURL := r.FormValue("webhook_url")

	if webhookURL != "" {
		if err := IsSafeURL(webhookURL); err != nil {
			http.Error(w, fmt.Sprintf("Webhook Security Restriction: %v", err), http.StatusForbidden)
			return
		}
	}
	if statusPageURL != "" {
		if err := IsSafeURL(statusPageURL); err != nil {
			http.Error(w, fmt.Sprintf("Status Page Security Restriction: %v", err), http.StatusForbidden)
			return
		}
	}

	m, err := db.CreateMonitor(ctx, sessionID, name, rawURL, statusPageURL, webhookURL)
	if err != nil {
		reqLog.Error("Failed to create monitor", "sessionID", sessionID, "url", rawURL, "error", err)
		http.Error(w, "Transaction Failed: Infrastructure could not be provisioned.", http.StatusInternalServerError)
		return
	}

	// Goroutine outlives the request — use its own context with timeout.
	go func(m db.Monitor, rawURL string) {
		gCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		monitor.PerformMonitorCheck(gCtx, &m)
		if u, err := url.Parse(rawURL); err == nil && (u.Scheme == "https" || u.Scheme == "http") {
			domain := u.Hostname()
			if domain != "" {
				s, err := db.CreateSSLCheck(gCtx, m.ID, domain)
				if err == nil {
					monitor.CheckAndSaveSSL(gCtx, s)
					monitor.RegisterSSLCheck(s)
				}
			}
		}
		monitor.RegisterMonitor(m)
	}(m, rawURL)

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Trigger", "registryUpdate")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDeleteMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !ValidateOrigin(r) {
		http.Error(w, "Security Violation: Untrusted origin", http.StatusForbidden)
		return
	}

	ctx := r.Context()
	reqLog := slog.With("request_id", RequestIDFromCtx(ctx))

	sessionID := getSessionID(w, r)
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := db.DeleteMonitor(ctx, id, sessionID); err != nil {
		reqLog.Error("Failed to delete monitor", "id", id, "sessionID", sessionID, "error", err)
		http.Error(w, "Transaction Failed: Unable to decommission monitor.", http.StatusInternalServerError)
		return
	}

	monitor.StopMonitor(id)

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Trigger", "registryUpdate")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, web.TemplateFS, "assets/logo.png")
}
