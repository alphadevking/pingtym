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
	MonitorHistory map[int][]int       // monitorID -> last 30 statuses [oldest...newest]
	LatencyHistory map[int][]int       // monitorID -> last 20 latencies (ms) [oldest...newest]
	SaaSHistory    map[string][]string // monitorID:serviceName -> last 20 statuses
	LastResults    map[int]CheckResult // monitorID -> last full check result
	FailureCounts  map[int]int         // monitorID -> consecutive failures
}

var (
	monitorContexts sync.Map // map[int]context.CancelFunc
	sslContexts     sync.Map // map[int]context.CancelFunc (keyed by monitorID)
	State           = &LiveState{
		MonitorHistory: make(map[int][]int),
		LatencyHistory: make(map[int][]int),
		SaaSHistory:    make(map[string][]string),
		LastResults:    make(map[int]CheckResult),
		FailureCounts:  make(map[int]int),
	}
)

func (s *LiveState) updateMonitorState(id int, status int, result CheckResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Append to the END (standard timeline: oldest...newest)
	history := s.MonitorHistory[id]
	history = append(history, status)
	if len(history) > 30 {
		history = history[1:] // Drop oldest
	}
	s.MonitorHistory[id] = history

	latencies := s.LatencyHistory[id]
	val := 0
	if result.Up {
		val = int(result.Latency.Milliseconds())
	}
	latencies = append(latencies, val)
	if len(latencies) > 20 {
		latencies = latencies[1:] // Drop oldest
	}
	s.LatencyHistory[id] = latencies

	s.LastResults[id] = result
}

func (s *LiveState) GetLatencyHistory(id int) []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]int, len(s.LatencyHistory[id]))
	copy(res, s.LatencyHistory[id])
	return res
}

func (s *LiveState) updateSaaSState(monitorID int, serviceName string, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%d:%s", monitorID, serviceName)
	history := s.SaaSHistory[key]
	history = append(history, status)
	if len(history) > 20 {
		history = history[1:]
	}
	s.SaaSHistory[key] = history
}

func (s *LiveState) GetMonitorHistory(id int) []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]int, len(s.MonitorHistory[id]))
	copy(res, s.MonitorHistory[id])
	return res
}

func (s *LiveState) GetLastResult(id int) CheckResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastResults[id]
}

func (s *LiveState) GetSaaSHistory(monitorID int, serviceName string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%d:%s", monitorID, serviceName)
	res := make([]string, len(s.SaaSHistory[key]))
	copy(res, s.SaaSHistory[key])
	return res
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
	for _, m := range monitors {
		wg.Add(1)
		go func(mon db.Monitor) {
			defer wg.Done()
			PerformMonitorCheck(&mon)
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

func PerformMonitorCheck(m *db.Monitor) {
	var lastStatus *int
	if m.LastStatus.Valid {
		ls := int(m.LastStatus.Int64)
		lastStatus = &ls
	}

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
		if count >= 3 && (lastStatus == nil || *lastStatus == 1) {
			shouldAlert = true
		}
	} else {
		State.mu.Lock()
		delete(State.FailureCounts, m.ID)
		State.mu.Unlock()
		if lastStatus != nil && *lastStatus == 0 {
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
	if err := db.SaveLog(m.ID, status, int(result.Latency.Milliseconds()), result.ErrorMessage); err != nil {
		slog.Error("Failed to save check log", "id", m.ID, "error", err)
	}

	if m.StatusPageURL.Valid && m.StatusPageURL.String != "" {
		statuses, err := CheckSaaSStatus(m.ID, m.StatusPageURL.String)
		if err != nil {
			slog.Warn("Failed to check SaaS status", "id", m.ID, "url", m.StatusPageURL.String, "error", err)
		} else {
			for _, s := range statuses {
				State.updateSaaSState(m.ID, s.ServiceName, s.Status)
				if err := db.UpdateSaaSStatus(m.ID, s.ServiceName, s.Status, s.Impact, s.LatestFix); err != nil {
					slog.Error("Failed to update SaaS status", "id", m.ID, "service", s.ServiceName, "error", err)
				}
				if err := db.SaveSaaSStatusLog(m.ID, s.ServiceName, s.Status); err != nil {
					slog.Error("Failed to save SaaS status log", "id", m.ID, "service", s.ServiceName, "error", err)
				}
			}
		}
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
