package main

import (
	"log/slog"
	"os"
	"pingtym/internal/db"
	"pingtym/internal/monitor"
	"pingtym/pkg/app"
)

func main() {
	// 1. Setup minimal environment
	app.LoadEnv()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Starting Pingtym Global Health Check Worker...")

	// 2. Connect to Database (Required by monitor engine)
	// Even if on GitHub Actions, this script needs the DB path/credentials to work
	// (usually fed by TURSO_DATABASE_URL environment variable).
	if err := db.InitDB("/tmp/pingtym_worker.db"); err != nil {
		slog.Error("FATAL: Failed to initialize database", "error", err)
		os.Exit(1)
	}

	// 3. Execute the global check (waits for all pinging and SaaS tracking to finish)
	monitor.RunGlobalCheck()

	slog.Info("Health check worker completed successfully.")
}
