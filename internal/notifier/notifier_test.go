package notifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendAlert(t *testing.T) {
	// Create a mock server that expects a JSON payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Verify content type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type: application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Decode the body to verify JSON structure
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("Failed to decode JSON body: %v", err)
			return
		}

		// Check if "text" field exists (simple check)
		if text, ok := payload["text"].(string); !ok || text == "" {
			t.Error("Expected 'text' field in JSON payload")
		}

		// Respond with success
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// content of the alert
	alert := Alert{
		MonitorName: "Test Monitor",
		URL:         "http://example.com",
		Status:      "DOWN",
		Latency:     "500ms",
		Error:       "Timeout",
	}

	// Call the function with the mock server URL
	// We are mainly testing that this doesn't panic and hits our server correctly
	SendAlert(server.URL, alert)
}
