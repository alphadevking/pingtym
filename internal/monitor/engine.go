package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"pingtym/internal/db"
	"pingtym/internal/notifier"
	"sync"
	"time"
)

type LiveState struct {
	mu             sync.RWMutex
	FailureCounts  map[int]int         // monitorID -> consecutive failures
}

var (
	monitorContexts sync.Map // map[int]context.CancelFunc
	sslContexts     sync.Map // map[int]context.CancelFunc (keyed by monitorID)
	State           = &LiveState{
		FailureCounts:  make(map[int]int),
	}
)

// We only need to track failures for alerting. Memory history is now DB-backed.
func (s *LiveState) updateMonitorState(id int, status int, result CheckResult) {
	// Alert logic doesn't strictly need state updates here anymore, it's handled in PerformMonitorCheck.
}

func (s *LiveState) updateSaaSState(monitorID int, serviceName string, status string) {
	// Memory history is now DB-backed. Let Vercel read it from there.
}

func StartEngine() {
	slog.Info("Monitoring engine started...")
	go startCleanupTask()

	monitors, err := db.GetAllActiveMonitors()
	if err != nil {
		slog.Error("Error fetching monitors", "error", err)
	}
	for _, m := range monitors {
		RegisterMonitor(m)
	}

	sslChecks, err := db.GetAllActiveSSLChecks()
	if err != nil {
		slog.Error("Error fetching SSL checks", "error", err)
	}
	for _, s := range sslChecks {
		RegisterSSLCheck(s)
	}
}

func RunGlobalCheck() {
	slog.Info("Executing global monitoring sweep...")
	monitors, _ := db.GetAllActiveMonitors()
	var wg sync.WaitGroup
	var saasWg sync.WaitGroup // Tracks detached SaaS status goroutines
	for _, m := range monitors {
		wg.Add(1)
		go func(mon db.Monitor) {
			defer wg.Done()
			PerformMonitorCheck(&mon, &saasWg)
		}(m)
	}
	sslChecks, _ := db.GetAllActiveSSLChecks()
	for _, s := range sslChecks {
		wg.Add(1)
		go func(ssl db.SSLCheck) {
			defer wg.Done()
			CheckAndSaveSSL(ssl)
		}(s)
	}
	wg.Wait()
	saasWg.Wait() // Critical: wait for all SaaS writes before returning (Vercel serverless)
}

func startCleanupTask() {
	if err := db.PruneLogs(30); err != nil {
		slog.Error("Failed to prune logs", "error", err)
	}
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		if err := db.PruneLogs(30); err != nil {
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
	if cancel, ok := monitorContexts.Load(id); ok {
		cancel.(context.CancelFunc)()
		monitorContexts.Delete(id)
	}
	if cancel, ok := sslContexts.Load(id); ok {
		cancel.(context.CancelFunc)()
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
	PerformMonitorCheck(&m)
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
			PerformMonitorCheck(&m)
		}
	}
}

// PerformMonitorCheck runs a full check for a single monitor.
// saasWg (optional) is used by RunGlobalCheck to track SaaS goroutines in
// serverless environments where the process exits after wg.Wait() returns.
func PerformMonitorCheck(m *db.Monitor, saasWg ...*sync.WaitGroup) {
	result := Ping(m.URL)
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
	State.updateMonitorState(m.ID, status, result)

	if err := db.UpdateMonitorStatus(m.ID, status); err != nil {
		slog.Error("Failed to update monitor status", "id", m.ID, "error", err)
	}
	if err := db.SaveLog(m.ID, status, int(result.Latency.Milliseconds()), int(result.DNS.Milliseconds()), int(result.TLS.Milliseconds()), int(result.TTFB.Milliseconds()), int(result.FullDuration.Milliseconds()), result.ErrorMessage); err != nil {
		slog.Error("Failed to save check log", "id", m.ID, "error", err)
	}

	// LATENCY FIX: Move SaaS checks off the critical monitoring path.
	// If a saasWg is provided (e.g. from RunGlobalCheck in serverless), track the
	// goroutine so it completes before the process exits.
	if m.StatusPageURL.Valid && m.StatusPageURL.String != "" {
		var wg *sync.WaitGroup
		if len(saasWg) > 0 && saasWg[0] != nil {
			wg = saasWg[0]
			wg.Add(1)
		}
		go func(id int, pageURL string) {
			if wg != nil {
				defer wg.Done()
			}
			statuses, err := CheckSaaSStatus(id, pageURL)
			if err != nil {
				slog.Warn("Failed to check SaaS status", "id", id, "url", pageURL, "error", err)
				return
			}
			for _, s := range statuses {
				State.updateSaaSState(id, s.ServiceName, s.Status)
				if err := db.UpdateSaaSStatus(id, s.ServiceName, s.Status, s.Impact, s.LatestFix); err != nil {
					slog.Error("Failed to update SaaS status", "id", id, "service", s.ServiceName, "error", err)
				}
				if err := db.SaveSaaSStatusLog(id, s.ServiceName, s.Status); err != nil {
					slog.Error("Failed to save SaaS status log", "id", id, "service", s.ServiceName, "error", err)
				}
			}
		}(m.ID, m.StatusPageURL.String)
	}
}

func triggerAlert(m db.Monitor, status int, result CheckResult) {
	statusStr := "DOWN"
	if status == 1 {
		statusStr = "UP"
	}
	if m.WebhookURL.Valid && m.WebhookURL.String != "" {
		go func() {
			alert := notifier.Alert{
				MonitorName: m.Name,
				URL:         m.URL,
				Status:      statusStr,
				Latency:     fmt.Sprintf("%dms", result.Latency.Milliseconds()),
				Error:       result.ErrorMessage,
			}
			_ = notifier.SendAlert(m.WebhookURL.String, alert)
		}()
	}
}

func watchSSL(ctx context.Context, s db.SSLCheck) {
	CheckAndSaveSSL(s)
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			CheckAndSaveSSL(s)
		}
	}
}

func CheckAndSaveSSL(s db.SSLCheck) {
	expiry, err := CheckSSL(s.Domain)
	if err == nil {
		_ = db.UpdateSSLCheck(s.ID, expiry)
	}
}
