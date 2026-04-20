package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type NotificationType string

const (
	Slack   NotificationType = "slack"
	Discord NotificationType = "discord"
	Email   NotificationType = "email"
)

type Alert struct {
	MonitorName string
	URL         string
	Status      string // "UP" or "DOWN"
	Latency     string
	Error       string
}

var webhookClient = &http.Client{Timeout: 10 * time.Second}

func SendAlert(ctx context.Context, webhookURL string, alert Alert) error {
	payload := map[string]string{
		"text": fmt.Sprintf("🚨 *Pingtym Alert* 🚨\n*Monitor:* %s\n*URL:* %s\n*Status:* %s\n*Latency:* %s\n*Error:* %s",
			alert.MonitorName, alert.URL, alert.Status, alert.Latency, alert.Error),
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal alert payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := webhookClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send alert: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status: %d", resp.StatusCode)
	}

	slog.Info("Alert sent successfully", "monitor", alert.MonitorName)
	return nil
}
