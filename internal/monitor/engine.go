package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"pingtym/internal/db"
	"pingtym/internal/notifier"
	"sync"
	"time"
)

type LiveState struct {
	mu            sync.RWMutex
	FailureCounts map[int]int // monitorID -> consecutive failures
}

var (
	monitorContexts sync.Map // map[int]context.CancelFunc
	sslContexts     sync.Map // map[int]context.CancelFunc (keyed by monitorID)
	State           = &LiveState{
		FailureCounts: make(map[int]int),
	}
)

func StartEngine() {
	slog.Info("Monitoring engine started...")
	go startCleanupTask()

	ctx := context.Background()
	monitors, err := db.GetAllActiveMonitors(ctx)
	if err != nil {
		slog.Error("Error fetching monitors", "error", err)
	}
	for _, m := range monitors {
		RegisterMonitor(m)
	}

	sslChecks, err := db.GetAllActiveSSLChecks(ctx)
	if err != nil {
		slog.Error("Error fetching SSL checks", "error", err)
	}
	for _, s := range sslChecks {
		RegisterSSLCheck(s)
	}
}

func RunGlobalCheck() {
	slog.Info("Executing global monitoring sweep...")
	ctx := context.Background()

	monitors, err := db.GetAllActiveMonitors(ctx)
	if err != nil {
		slog.Error("Failed to fetch monitors for global check", "error", err)
	}

	var wg sync.WaitGroup
	var saasWg sync.WaitGroup
	for _, m := range monitors {
		wg.Add(1)
		go func(mon db.Monitor) {
			defer wg.Done()
			PerformMonitorCheck(ctx, &mon, &saasWg)
		}(m)
	}

	sslChecks, err := db.GetAllActiveSSLChecks(ctx)
	if err != nil {
		slog.Error("Failed to fetch SSL checks for global check", "error", err)
	}
	for _, s := range sslChecks {
		wg.Add(1)
		go func(ssl db.SSLCheck) {
			defer wg.Done()
			CheckAndSaveSSL(ctx, ssl)
		}(s)
	}

	wg.Wait()
	saasWg.Wait()
}

func startCleanupTask() {
	ctx := context.Background()
	if err := db.PruneLogs(ctx, 30); err != nil {
		slog.Error("Failed to prune logs", "error", err)
	}
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		if err := db.PruneLogs(ctx, 30); err != nil {
			slog.Error("Failed to prune logs", "error", err)
		}
	}
}

func RegisterMonitor(m db.Monitor) {
	StopMonitor(m.ID)
	ctx, cancel := context.WithCancel(context.Background())
	monitorContexts.Store(m.ID, cancel)
	slog.Info("Registering monitor", "name", m.Name, "url", m.URL)
	go watchMonitor(ctx, m)
}

func StopMonitor(id int) {
	if v, ok := monitorContexts.Load(id); ok {
		if fn, ok := v.(context.CancelFunc); ok {
			fn()
		}
		monitorContexts.Delete(id)
	}
	if v, ok := sslContexts.Load(id); ok {
		if fn, ok := v.(context.CancelFunc); ok {
			fn()
		}
		sslContexts.Delete(id)
	}
	State.mu.Lock()
	delete(State.FailureCounts, id)
	State.mu.Unlock()
}

func RegisterSSLCheck(s db.SSLCheck) {
	ctx, cancel := context.WithCancel(context.Background())
	sslContexts.Store(s.MonitorID, cancel)
	go watchSSL(ctx, s)
}

func watchMonitor(ctx context.Context, m db.Monitor) {
	PerformMonitorCheck(ctx, &m)
	interval := m.IntervalSeconds
	if interval <= 0 {
		interval = 60
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			PerformMonitorCheck(ctx, &m)
		}
	}
}

// PerformMonitorCheck runs a full check for a single monitor.
// saasWg (optional) is used by RunGlobalCheck to track SaaS goroutines in
// serverless environments where the process exits after wg.Wait() returns.
func PerformMonitorCheck(ctx context.Context, m *db.Monitor, saasWg ...*sync.WaitGroup) {
	result := Ping(ctx, m.URL)
	status := 0
	if result.Up {
		status = 1
	}

	shouldAlert := false
	if status == 0 {
		State.mu.Lock()
		count := State.FailureCounts[m.ID] + 1
		State.FailureCounts[m.ID] = count
		State.mu.Unlock()
		if count == 3 {
			shouldAlert = true
		}
	} else {
		State.mu.Lock()
		count := State.FailureCounts[m.ID]
		delete(State.FailureCounts, m.ID)
		State.mu.Unlock()
		if count >= 3 {
			shouldAlert = true
		}
	}

	if shouldAlert {
		triggerAlert(*m, status, result)
	}

	m.LastStatus.Valid = true
	m.LastStatus.Int64 = int64(status)

	if err := db.UpdateMonitorStatus(ctx, m.ID, status); err != nil {
		slog.Error("Failed to update monitor status", "id", m.ID, "error", err)
	}
	if err := db.SaveLog(ctx, m.ID, status, int(result.Latency.Milliseconds()), int(result.DNS.Milliseconds()), int(result.TLS.Milliseconds()), int(result.TTFB.Milliseconds()), int(result.FullDuration.Milliseconds()), result.ErrorMessage); err != nil {
		slog.Error("Failed to save check log", "id", m.ID, "error", err)
	}

	if m.StatusPageURL.Valid && m.StatusPageURL.String != "" {
		pageURL := m.StatusPageURL.String
		// Re-validate status page URL before fetching (defense-in-depth against DB tampering).
		if u, err := url.Parse(pageURL); err != nil || validateSSRF(u) != nil {
			slog.Warn("Skipping SaaS check: status page URL failed SSRF re-validation", "id", m.ID, "url", pageURL)
		} else {
			var wg *sync.WaitGroup
			if len(saasWg) > 0 && saasWg[0] != nil {
				wg = saasWg[0]
				wg.Add(1)
			}
			go func(id int, pURL string) {
				if wg != nil {
					defer wg.Done()
				}
				statuses, err := CheckSaaSStatus(ctx, id, pURL)
				if err != nil {
					slog.Warn("Failed to check SaaS status", "id", id, "url", pURL, "error", err)
					return
				}
				for _, s := range statuses {
					if err := db.UpdateSaaSStatus(ctx, id, s.ServiceName, s.Status, s.Impact, s.LatestFix); err != nil {
						slog.Error("Failed to update SaaS status", "id", id, "service", s.ServiceName, "error", err)
					}
					if err := db.SaveSaaSStatusLog(ctx, id, s.ServiceName, s.Status); err != nil {
						slog.Error("Failed to save SaaS status log", "id", id, "service", s.ServiceName, "error", err)
					}
				}
			}(m.ID, pageURL)
		}
	}
}

func triggerAlert(m db.Monitor, status int, result CheckResult) {
	if !m.WebhookURL.Valid || m.WebhookURL.String == "" {
		return
	}
	// Re-validate webhook URL before sending (defense-in-depth against DB tampering).
	u, err := url.Parse(m.WebhookURL.String)
	if err != nil || validateSSRF(u) != nil {
		slog.Error("Webhook URL failed SSRF re-validation, skipping alert", "id", m.ID, "url", m.WebhookURL.String)
		return
	}

	statusStr := "DOWN"
	if status == 1 {
		statusStr = "UP"
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		alert := notifier.Alert{
			MonitorName: m.Name,
			URL:         m.URL,
			Status:      statusStr,
			Latency:     fmt.Sprintf("%dms", result.Latency.Milliseconds()),
			Error:       result.ErrorMessage,
		}
		if err := notifier.SendAlert(ctx, m.WebhookURL.String, alert); err != nil {
			slog.Error("Failed to send alert", "monitor", m.Name, "webhook", m.WebhookURL.String, "error", err)
		}
	}()
}

func watchSSL(ctx context.Context, s db.SSLCheck) {
	CheckAndSaveSSL(ctx, s)
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			CheckAndSaveSSL(ctx, s)
		}
	}
}

func CheckAndSaveSSL(ctx context.Context, s db.SSLCheck) {
	expiry, err := CheckSSL(s.Domain)
	if err != nil {
		slog.Error("SSL check failed", "domain", s.Domain, "error", err)
		return
	}
	if err := db.UpdateSSLCheck(ctx, s.ID, expiry); err != nil {
		slog.Error("Failed to save SSL expiry", "domain", s.Domain, "error", err)
	}
}
