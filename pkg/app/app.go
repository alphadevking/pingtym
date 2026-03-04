package app

import (
	"bufio"
	"log/slog"
	"net/http"
	"os"
	"pingtym/internal/api"
	"pingtym/internal/db"
	"pingtym/internal/monitor"
	"strings"
	"sync"
	"time"
)

var (
	initOnce sync.Once
	handler  http.Handler
)

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
			if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
				val = val[1 : len(val)-1]
			}
			os.Setenv(key, val)
		}
	}
}

// Setup initializes the application components with retry logic
func Setup() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	isVercel := os.Getenv("VERCEL") == "1"
	
	dbPath := "pingtym.db"
	if isVercel {
		dbPath = "/tmp/pingtym.db"
	}

	maxRetries := 3
	var err error
	for i := 1; i <= maxRetries; i++ {
		err = db.InitDB(dbPath)
		if err == nil {
			break
		}
		
		slog.Warn("Database connection attempt failed", "attempt", i, "max_retries", maxRetries, "error", err)
		if i < maxRetries {
			time.Sleep(2 * time.Second)
		}
	}

	if err != nil {
		slog.Error("FATAL: Database could not be initialized after retries. Stopping server.", "error", err)
		// Exit process to prevent running in an unstable state
		os.Exit(1)
	}

	if !isVercel {
		monitor.StartEngine()
	}
}

// Handler is the entry point for Vercel Serverless Functions
func Handler(w http.ResponseWriter, r *http.Request) {
	initOnce.Do(func() {
		LoadEnv()
		api.InitSession()
		Setup()
		handler = api.GetGlobalHandler()
	})
	handler.ServeHTTP(w, r)
}
