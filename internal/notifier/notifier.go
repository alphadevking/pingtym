package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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

func SendAlert(webhookURL string, alert Alert) error {
	// For this MVP, we'll implement a generic JSON webhook (Slack/Discord style)
	payload := map[string]string{
		"text": fmt.Sprintf("🚨 *Pingtym Alert* 🚨\n*Monitor:* %s\n*URL:* %s\n*Status:* %s\n*Latency:* %s\n*Error:* %s",
			alert.MonitorName, alert.URL, alert.Status, alert.Latency, alert.Error),
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal alert payload: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status: %d", resp.StatusCode)
	}

	slog.Info("Alert sent successfully", "monitor", alert.MonitorName)
	return nil
}
