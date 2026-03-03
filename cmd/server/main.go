package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"pingtym/internal/api"
	"pingtym/internal/db"
	"pingtym/internal/monitor"
	"sync"
	"syscall"
	"time"
)

var initOnce sync.Once

// Handler is the entry point for Vercel Serverless Functions
func Handler(w http.ResponseWriter, r *http.Request) {
	initOnce.Do(func() {
		setup()
	})
	api.RegisterHandlers()
	http.DefaultServeMux.ServeHTTP(w, r)
}

func setup() {
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

func main() {
	setup()
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	host := "127.0.0.1"
	if os.Getenv("ENV") == "production" {
		host = "0.0.0.0"
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	api.RegisterHandlers()
	
	server := &http.Server{
		Addr: addr,
	}

	go func() {
		slog.Info("Pingtym Insight Service", "url", fmt.Sprintf("http://%s", addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}
