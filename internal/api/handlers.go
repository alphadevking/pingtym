package api

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"pingtym/internal/db"
	"pingtym/internal/monitor"
	"pingtym/web"
	"strconv"
	"time"
)

var startTime = time.Now()

var templates *template.Template

func loadTemplates() error {
	var err error
	templates, err = template.New("index.html").Funcs(template.FuncMap{
		"until": func(n int) []int {
			res := make([]int, n)
			for i := range res {
				res[i] = i
			}
			return res
		},
		"multiply": func(a, b int) int { return a * b },
		"divide":   func(a, b int) int { if b == 0 { return a }; return a / b },
		"minus":    func(a, b int) int { return a - b },
		"floatDiv": func(a, b int) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
		"sparkPoint": func(val, max, height int) float64 {
			if max == 0 {
				return float64(height)
			}
			// Calculate Y coordinate: height - (val / max * height)
			// We use 80% of height (24px out of 30px) for the peak to keep it in view
			ratio := float64(val) / float64(max)
			if ratio > 1.0 { ratio = 1.0 }
			return float64(height) - (ratio * float64(height) * 0.8)
		},
	}).ParseFS(web.TemplateFS, "templates/index.html", "templates/learn.html")
	
	if err != nil {
		return fmt.Errorf("failed to parse template from embed: %w", err)
	}

	slog.Info("Templates loaded successfully from embedded filesystem")
	return nil
}

func RegisterHandlers() {
	if err := loadTemplates(); err != nil {
		slog.Error("Initial template load failed", "error", err)
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/learn", handleLearn)
	http.HandleFunc("/favicon.ico", handleFavicon)
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(web.TemplateFS))))
	http.HandleFunc("/add-monitor", handleAddMonitor)
	http.HandleFunc("/delete-monitor", handleDeleteMonitor)
	http.HandleFunc("/api/cron", handleCron)
}

func handleLearn(w http.ResponseWriter, r *http.Request) {
	if err := templates.ExecuteTemplate(w, "learn.html", nil); err != nil {
		slog.Error("Failed to execute learn template", "error", err)
	}
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
	
	// Retry loading templates if they are nil (fallback for hot fixes)
	if templates == nil {
		if err := loadTemplates(); err != nil {
			http.Error(w, "Critical Error: Templates not found. Please ensure 'web/templates' exists in the project root.", http.StatusInternalServerError)
			return
		}
	}

	sessionID := getSessionID(w, r)
	monitors, err := db.GetMonitors(sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var monitorViews []MonitorView
	var totalUptime float64
	downCount := 0

	for _, m := range monitors {
		statuses, _ := db.GetSaaSStatuses(m.ID)
		history := monitor.State.GetMonitorHistory(m.ID)
		lastRes := monitor.State.GetLastResult(m.ID)

		for i := range statuses {
			statuses[i].History = monitor.State.GetSaaSHistory(m.ID, statuses[i].ServiceName)
		}
		
		u24h, _ := db.GetUptimePercentage(m.ID, 24*time.Hour)
		u7d, _ := db.GetUptimePercentage(m.ID, 7*24*time.Hour)
		avgLat, _ := db.GetAverageLatency(m.ID, 24*time.Hour)
		latencyHistory := monitor.State.GetLatencyHistory(m.ID)
		
		maxLat := 0
		for _, v := range latencyHistory {
			if v > maxLat {
				maxLat = v
			}
		}
		// Minimum scale of 100ms for visual consistency
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

	sslChecks, err := db.GetSSLChecks(sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sslViews := []SSLView{}
	for _, s := range sslChecks {
		days := 0
		if s.ExpiryDate.Valid {
			days = int(time.Until(s.ExpiryDate.Time).Hours() / 24)
		}
		sslViews = append(sslViews, SSLView{SSLCheck: s, DaysLeft: days})
	}

	userInfo := struct {
		SessionID string
		Identity  string
		Since     string
	}{
		SessionID: sessionID,
		Identity:  fmt.Sprintf("User-%s", sessionID[:8]),
		Since:     time.Now().Format("Jan 2006"), // Simplified since we don't track join date yet
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

	if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {

		slog.Error("Failed to execute template", "error", err)
	}
}

func handleAddMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := getSessionID(w, r)
	name := r.FormValue("name")
	rawURL := r.FormValue("url")
	statusPageURL := r.FormValue("status_page_url")
	webhookURL := r.FormValue("webhook_url")

	if name == "" || rawURL == "" {
		http.Error(w, "Name and URL are required", http.StatusBadRequest)
		return
	}

	m, err := db.CreateMonitor(sessionID, name, rawURL, statusPageURL, webhookURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 1. Perform first monitor check synchronously
	monitor.PerformMonitorCheck(&m)

	// 2. Extract domain and perform first SSL check synchronously
	if u, err := url.Parse(rawURL); err == nil && (u.Scheme == "https" || u.Scheme == "http") {
		domain := u.Hostname()
		if domain != "" {
			s, err := db.CreateSSLCheck(m.ID, domain)
			if err == nil {
				monitor.CheckAndSaveSSL(s) // Sync check for Gold Standard UX
				monitor.RegisterSSLCheck(s) // Background loop
			}
		}
	}

	monitor.RegisterMonitor(m)

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func ensureSSLCheck(monitorID int, domain string) {
	s, err := db.CreateSSLCheck(monitorID, domain)
	if err == nil {
		monitor.RegisterSSLCheck(s)
	}
}

func handleDeleteMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := getSessionID(w, r)
	idStr := r.FormValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := db.DeleteMonitor(id, sessionID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	monitor.StopMonitor(id)

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleCron(w http.ResponseWriter, r *http.Request) {
	monitor.RunGlobalCheck()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Global check complete"))
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	favicon := `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect width='24' height='24' rx='6' fill='#10b981'/><polyline points='22 12 18 12 15 21 9 3 6 12 2 12' fill='none' stroke='white' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'/></svg>`
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write([]byte(favicon))
}
