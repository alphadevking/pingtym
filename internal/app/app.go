package app

import (
	"bufio"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"pingtym/internal/api"
	"pingtym/internal/db"
	"pingtym/internal/monitor"
	"strings"
	"sync"
)

var initOnce sync.Once

// LoadEnv reads a .env file and sets environment variables
func LoadEnv() {
	file, err := os.Open(".env")
	if err != nil {
		return // No .env file, ignore
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// Handle quoted values
			if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
				val = val[1 : len(val)-1]
			}
			os.Setenv(key, val)
		}
	}
}

// Setup initializes the application components
func Setup() {
	// Setup structured logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Use /tmp for SQLite in Serverless environments
	dbPath := "pingtym.db"
	if os.Getenv("VERCEL") == "1" {
		dbPath = "/tmp/pingtym.db"
	}

	if err := db.InitDB(dbPath); err != nil {
		slog.Error("Failed to initialize database", "error", err)
	}

	// Only start background engine if not in serverless mode
	if os.Getenv("VERCEL") != "1" {
		monitor.StartEngine()
	}
}

// Handler is the entry point for Vercel Serverless Functions
func Handler(w http.ResponseWriter, r *http.Request) {
	initOnce.Do(func() {
		LoadEnv()
		api.InitSession()
		Setup()
		api.RegisterHandlers()
	})
	http.DefaultServeMux.ServeHTTP(w, r)
}
