package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

const sessionCookieName = "pingtym_session"

// In production, this must be a strong 32-byte string from an environment variable
var sessionSecret []byte

func InitSession() {
	envSecret := os.Getenv("SESSION_SECRET")
	if envSecret != "" {
		sessionSecret = []byte(envSecret)
		return
	}

	isProd := os.Getenv("VERCEL") == "1" || os.Getenv("ENV") == "production"
	if isProd {
		slog.Error("FATAL: SESSION_SECRET is not set in production! Deployment aborted for security.")
		// In production, we must stop the process. Placeholder keys are a security risk.
		os.Exit(1)
	} else {
		slog.Warn("SESSION_SECRET not found in .env. Using ephemeral development fallback.")
		sessionSecret = []byte("pingtym-dev-ephemeral-secret-key-2026")
	}
}

func signID(id string) string {
	h := hmac.New(sha256.New, sessionSecret)
	h.Write([]byte(id))
	return fmt.Sprintf("%s.%s", id, hex.EncodeToString(h.Sum(nil)))
}

func verifyID(signedID string) (string, bool) {
	parts := strings.Split(signedID, ".")
	if len(parts) != 2 {
		return "", false
	}
	id, sig := parts[0], parts[1]

	h := hmac.New(sha256.New, sessionSecret)
	h.Write([]byte(id))
	expectedSig := hex.EncodeToString(h.Sum(nil))

	if hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return id, true
	}
	return "", false
}

func getSessionID(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		if id, ok := verifyID(cookie.Value); ok {
			return id
		}
	}

	// Create new session
	newID := uuid.New().String()
	signedID := signID(newID)
	isProd := os.Getenv("VERCEL") == "1" || os.Getenv("ENV") == "production"

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signedID,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   isProd,
		SameSite: http.SameSiteLaxMode,
	})
	return newID
}
