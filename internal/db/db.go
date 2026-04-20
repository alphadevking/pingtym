package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"time"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
	_ "modernc.org/sqlite"
)

var DB *sql.DB

// identifierRe guards columnExists against SQL injection via table/column names.
var identifierRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

type Monitor struct {
	ID              int
	SessionID       string
	Name            string
	URL             string
	IntervalSeconds int
	LastStatus      sql.NullInt64
	LastChecked     sql.NullTime
	StatusPageURL   sql.NullString
	WebhookURL      sql.NullString
	CreatedAt       time.Time
}

type SaaSServiceStatus struct {
	ID          int
	MonitorID   int
	ServiceName string
	Status      string
	Impact      string
	LatestFix   string
	LastChecked time.Time
	History     []string
}

type SSLCheck struct {
	ID          int
	MonitorID   int
	Domain      string
	ExpiryDate  sql.NullTime
	LastChecked sql.NullTime
}

type CheckLog struct {
	Status       int
	LatencyMs    int
	DNSMs        int
	TLSMs        int
	TTFBMs       int
	TotalMs      int
	ErrorMessage string
}

func InitDB(dataSourceName string) error {
	var err error
	var driverName string
	var dsn string

	tursoURL := os.Getenv("TURSO_DATABASE_URL")
	tursoToken := os.Getenv("TURSO_AUTH_TOKEN")

	if tursoURL != "" {
		driverName = "libsql"
		if tursoToken != "" {
			dsn = fmt.Sprintf("%s?authToken=%s", tursoURL, tursoToken)
		} else {
			dsn = tursoURL
		}
		slog.Info("Attempting to connect to Turso (libSQL) database")
	} else {
		driverName = "sqlite"
		dsn = fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", dataSourceName)
		slog.Info("Using local SQLite database", "path", dataSourceName)
	}

	DB, err = sql.Open(driverName, dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if driverName == "sqlite" {
		DB.SetMaxOpenConns(1)
	} else {
		DB.SetMaxOpenConns(10)
		DB.SetMaxIdleConns(5)
		DB.SetConnMaxLifetime(time.Hour)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err = DB.PingContext(ctx); err != nil {
		return fmt.Errorf("database connectivity check failed: %w", err)
	}

	if err := createTablesContext(ctx); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	if err := migrateSchema(ctx); err != nil {
		return fmt.Errorf("schema migration failed: %w", err)
	}

	slog.Info("Database initialized successfully", "driver", driverName)
	return nil
}

func createTablesContext(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS monitors (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL DEFAULT 'legacy',
			name TEXT NOT NULL,
			url TEXT NOT NULL,
			interval_seconds INTEGER DEFAULT 60,
			last_status INTEGER,
			last_checked DATETIME,
			status_page_url TEXT,
			webhook_url TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS ssl_checks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			monitor_id INTEGER NOT NULL,
			domain TEXT NOT NULL,
			expiry_date DATETIME,
			last_checked DATETIME,
			FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS check_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			monitor_id INTEGER,
			status INTEGER,
			latency_ms INTEGER,
			dns_ms INTEGER DEFAULT 0,
			tls_ms INTEGER DEFAULT 0,
			ttfb_ms INTEGER DEFAULT 0,
			total_ms INTEGER DEFAULT 0,
			error_message TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS saas_service_status (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			monitor_id INTEGER,
			service_name TEXT NOT NULL,
			status TEXT NOT NULL,
			impact TEXT,
			latest_fix TEXT,
			last_checked DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE,
			UNIQUE(monitor_id, service_name)
		);`,
		`CREATE TABLE IF NOT EXISTS saas_status_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			monitor_id INTEGER,
			service_name TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
		);`,
	}

	for _, query := range queries {
		if _, err := DB.ExecContext(ctx, query); err != nil {
			return err
		}
	}

	_, _ = DB.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_monitors_session ON monitors(session_id)")
	_, _ = DB.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_ssl_monitor ON ssl_checks(monitor_id)")
	_, _ = DB.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_check_logs_composite ON check_logs(monitor_id, created_at)")
	_, _ = DB.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_saas_status_monitor ON saas_service_status(monitor_id)")

	return nil
}

func migrateSchema(ctx context.Context) error {
	if !columnExists("monitors", "created_at") {
		if _, err := DB.ExecContext(ctx, "ALTER TABLE monitors ADD COLUMN created_at DATETIME"); err != nil {
			return fmt.Errorf("add monitors.created_at: %w", err)
		}
		if _, err := DB.ExecContext(ctx, "UPDATE monitors SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"); err != nil {
			slog.Warn("Failed to backfill monitors.created_at", "error", err)
		}
	}

	monitorCols := map[string]string{
		"session_id":      "TEXT NOT NULL DEFAULT 'legacy'",
		"status_page_url": "TEXT",
		"webhook_url":     "TEXT",
	}
	for col, definition := range monitorCols {
		if !columnExists("monitors", col) {
			if _, err := DB.ExecContext(ctx, fmt.Sprintf("ALTER TABLE monitors ADD COLUMN %s %s", col, definition)); err != nil {
				return fmt.Errorf("add monitors.%s: %w", col, err)
			}
		}
	}

	checkLogCols := map[string]string{
		"dns_ms":   "INTEGER DEFAULT 0",
		"tls_ms":   "INTEGER DEFAULT 0",
		"ttfb_ms":  "INTEGER DEFAULT 0",
		"total_ms": "INTEGER DEFAULT 0",
	}
	for col, definition := range checkLogCols {
		if !columnExists("check_logs", col) {
			if _, err := DB.ExecContext(ctx, fmt.Sprintf("ALTER TABLE check_logs ADD COLUMN %s %s", col, definition)); err != nil {
				return fmt.Errorf("add check_logs.%s: %w", col, err)
			}
		}
	}

	if !columnExists("ssl_checks", "monitor_id") {
		if _, err := DB.ExecContext(ctx, "ALTER TABLE ssl_checks ADD COLUMN monitor_id INTEGER REFERENCES monitors(id) ON DELETE CASCADE"); err != nil {
			return fmt.Errorf("add ssl_checks.monitor_id: %w", err)
		}
	}

	return nil
}

func columnExists(tableName, columnName string) bool {
	if !identifierRe.MatchString(tableName) || !identifierRe.MatchString(columnName) {
		slog.Error("columnExists called with unsafe identifier", "table", tableName, "column", columnName)
		return false
	}
	var name string
	query := fmt.Sprintf("SELECT name FROM pragma_table_info('%s') WHERE name='%s'", tableName, columnName)
	err := DB.QueryRow(query).Scan(&name)
	return err == nil
}

func PruneLogs(ctx context.Context, days int) error {
	cutoff := time.Now().AddDate(0, 0, -days).Format("2006-01-02 15:04:05")
	if _, err := DB.ExecContext(ctx, "DELETE FROM check_logs WHERE created_at < ?", cutoff); err != nil {
		return err
	}
	_, err := DB.ExecContext(ctx, "DELETE FROM saas_status_logs WHERE created_at < ?", cutoff)
	return err
}

func CreateMonitor(ctx context.Context, sessionID, name, url, statusPageURL, webhookURL string) (Monitor, error) {
	now := time.Now().UTC()
	res, err := DB.ExecContext(ctx, "INSERT INTO monitors (session_id, name, url, status_page_url, webhook_url, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		sessionID, name, url, statusPageURL, webhookURL, now)
	if err != nil {
		return Monitor{}, err
	}

	id, _ := res.LastInsertId()
	return Monitor{
		ID:              int(id),
		SessionID:       sessionID,
		Name:            name,
		URL:             url,
		IntervalSeconds: 60,
		StatusPageURL:   sql.NullString{String: statusPageURL, Valid: statusPageURL != ""},
		WebhookURL:      sql.NullString{String: webhookURL, Valid: webhookURL != ""},
		CreatedAt:       now,
	}, nil
}

func GetMonitors(ctx context.Context, sessionID string) ([]Monitor, error) {
	rows, err := DB.QueryContext(ctx, "SELECT id, session_id, name, url, interval_seconds, last_status, last_checked, status_page_url, webhook_url, created_at FROM monitors WHERE session_id = ?", sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var monitors []Monitor
	for rows.Next() {
		var m Monitor
		if err := rows.Scan(&m.ID, &m.SessionID, &m.Name, &m.URL, &m.IntervalSeconds, &m.LastStatus, &m.LastChecked, &m.StatusPageURL, &m.WebhookURL, &m.CreatedAt); err != nil {
			return nil, err
		}
		monitors = append(monitors, m)
	}
	return monitors, rows.Err()
}

func GetAllActiveMonitors(ctx context.Context) ([]Monitor, error) {
	rows, err := DB.QueryContext(ctx, "SELECT id, session_id, name, url, interval_seconds, last_status, last_checked, status_page_url, webhook_url, created_at FROM monitors")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var monitors []Monitor
	for rows.Next() {
		var m Monitor
		if err := rows.Scan(&m.ID, &m.SessionID, &m.Name, &m.URL, &m.IntervalSeconds, &m.LastStatus, &m.LastChecked, &m.StatusPageURL, &m.WebhookURL, &m.CreatedAt); err != nil {
			return nil, err
		}
		monitors = append(monitors, m)
	}
	return monitors, rows.Err()
}

func DeleteMonitor(ctx context.Context, id int, sessionID string) error {
	_, err := DB.ExecContext(ctx, "DELETE FROM monitors WHERE id = ? AND session_id = ?", id, sessionID)
	return err
}

func UpdateMonitorStatus(ctx context.Context, id int, status int) error {
	_, err := DB.ExecContext(ctx, "UPDATE monitors SET last_status = ?, last_checked = ? WHERE id = ?", status, time.Now().UTC(), id)
	return err
}

func SaveLog(ctx context.Context, monitorID int, status int, latency int, dnsMs, tlsMs, ttfbMs, totalMs int, errMsg string) error {
	_, err := DB.ExecContext(ctx, "INSERT INTO check_logs (monitor_id, status, latency_ms, dns_ms, tls_ms, ttfb_ms, total_ms, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		monitorID, status, latency, dnsMs, tlsMs, ttfbMs, totalMs, errMsg)
	return err
}

func GetRecentLogs(ctx context.Context, monitorID int, limit int) ([]CheckLog, error) {
	rows, err := DB.QueryContext(ctx, `
		SELECT status, latency_ms, dns_ms, tls_ms, ttfb_ms, total_ms, error_message
		FROM check_logs
		WHERE monitor_id = ?
		ORDER BY created_at DESC LIMIT ?`, monitorID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []CheckLog
	for rows.Next() {
		var l CheckLog
		var dns, tls, ttfb, total sql.NullInt64
		var errMsg sql.NullString
		if err := rows.Scan(&l.Status, &l.LatencyMs, &dns, &tls, &ttfb, &total, &errMsg); err != nil {
			return nil, err
		}
		if dns.Valid {
			l.DNSMs = int(dns.Int64)
		}
		if tls.Valid {
			l.TLSMs = int(tls.Int64)
		}
		if ttfb.Valid {
			l.TTFBMs = int(ttfb.Int64)
		}
		if total.Valid {
			l.TotalMs = int(total.Int64)
		}
		if errMsg.Valid {
			l.ErrorMessage = errMsg.String
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

func GetSSLChecks(ctx context.Context, sessionID string) ([]SSLCheck, error) {
	rows, err := DB.QueryContext(ctx, `SELECT s.id, s.monitor_id, s.domain, s.expiry_date, s.last_checked
		FROM ssl_checks s
		JOIN monitors m ON s.monitor_id = m.id
		WHERE m.session_id = ?`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var checks []SSLCheck
	for rows.Next() {
		var c SSLCheck
		if err := rows.Scan(&c.ID, &c.MonitorID, &c.Domain, &c.ExpiryDate, &c.LastChecked); err != nil {
			return nil, err
		}
		checks = append(checks, c)
	}
	return checks, rows.Err()
}

func GetAllActiveSSLChecks(ctx context.Context) ([]SSLCheck, error) {
	rows, err := DB.QueryContext(ctx, "SELECT id, monitor_id, domain, expiry_date, last_checked FROM ssl_checks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var checks []SSLCheck
	for rows.Next() {
		var c SSLCheck
		if err := rows.Scan(&c.ID, &c.MonitorID, &c.Domain, &c.ExpiryDate, &c.LastChecked); err != nil {
			return nil, err
		}
		checks = append(checks, c)
	}
	return checks, rows.Err()
}

func CreateSSLCheck(ctx context.Context, monitorID int, domain string) (SSLCheck, error) {
	res, err := DB.ExecContext(ctx, "INSERT OR IGNORE INTO ssl_checks (monitor_id, domain) VALUES (?, ?)", monitorID, domain)
	if err != nil {
		return SSLCheck{}, err
	}
	id, _ := res.LastInsertId()
	return SSLCheck{ID: int(id), MonitorID: monitorID, Domain: domain}, nil
}

func UpdateSSLCheck(ctx context.Context, id int, expiry time.Time) error {
	_, err := DB.ExecContext(ctx, "UPDATE ssl_checks SET expiry_date = ?, last_checked = ? WHERE id = ?", expiry, time.Now().UTC(), id)
	return err
}

func GetUptimePercentage(ctx context.Context, monitorID int, duration time.Duration) (float64, error) {
	since := time.Now().UTC().Add(-duration)
	var total, up int
	err := DB.QueryRowContext(ctx, "SELECT COUNT(*), SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) FROM check_logs WHERE monitor_id = ? AND created_at > ?",
		monitorID, since).Scan(&total, &up)
	if err != nil || total == 0 {
		return 100.0, nil
	}
	return (float64(up) / float64(total)) * 100, nil
}

func GetAverageLatency(ctx context.Context, monitorID int, duration time.Duration) (int, error) {
	since := time.Now().UTC().Add(-duration)
	var avg sql.NullFloat64
	err := DB.QueryRowContext(ctx, "SELECT AVG(latency_ms) FROM check_logs WHERE monitor_id = ? AND created_at > ?",
		monitorID, since).Scan(&avg)
	if err != nil || !avg.Valid {
		return 0, nil
	}
	return int(avg.Float64), nil
}

func UpdateSaaSStatus(ctx context.Context, monitorID int, serviceName, status, impact, latestFix string) error {
	_, err := DB.ExecContext(ctx, `INSERT INTO saas_service_status
		(monitor_id, service_name, status, impact, latest_fix, last_checked)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(monitor_id, service_name) DO UPDATE SET
		status = excluded.status, impact = excluded.impact, latest_fix = excluded.latest_fix, last_checked = excluded.last_checked`,
		monitorID, serviceName, status, impact, latestFix, time.Now().UTC())
	return err
}

func SaveSaaSStatusLog(ctx context.Context, monitorID int, serviceName, status string) error {
	_, err := DB.ExecContext(ctx, "INSERT INTO saas_status_logs (monitor_id, service_name, status) VALUES (?, ?, ?)",
		monitorID, serviceName, status)
	return err
}

func GetRecentSaaSLogStatuses(ctx context.Context, monitorID int, serviceName string, limit int) ([]string, error) {
	rows, err := DB.QueryContext(ctx, `SELECT status FROM saas_status_logs WHERE monitor_id = ? AND service_name = ? ORDER BY created_at DESC LIMIT ?`,
		monitorID, serviceName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []string
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			return nil, err
		}
		logs = append(logs, status)
	}
	return logs, rows.Err()
}

func GetSaaSStatuses(ctx context.Context, monitorID int) ([]SaaSServiceStatus, error) {
	rows, err := DB.QueryContext(ctx, "SELECT id, monitor_id, service_name, status, impact, latest_fix, last_checked FROM saas_service_status WHERE monitor_id = ?", monitorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []SaaSServiceStatus
	for rows.Next() {
		var s SaaSServiceStatus
		if err := rows.Scan(&s.ID, &s.MonitorID, &s.ServiceName, &s.Status, &s.Impact, &s.LatestFix, &s.LastChecked); err != nil {
			return nil, err
		}
		statuses = append(statuses, s)
	}
	return statuses, rows.Err()
}
