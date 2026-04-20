package api

import (
	crand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
)

const devSecretFile = ".dev-session-secret"

const (
	sessionCookieName = "pingtym_session"
	sessionMaxAge     = 30 * 24 * 3600 // 30 days in seconds
)

// In production, this must be a strong 32-byte string from an environment variable.
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
		os.Exit(1)
	}

	// In dev, persist the secret to a local file so sessions survive restarts.
	// The file is gitignored and never used in production.
	if raw, err := os.ReadFile(devSecretFile); err == nil && len(raw) == 64 {
		secret, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err == nil && len(secret) == 32 {
			sessionSecret = secret
			slog.Info("SESSION_SECRET not set. Loaded persisted dev secret from " + devSecretFile)
			return
		}
	}

	secret := make([]byte, 32)
	if _, err := crand.Read(secret); err != nil {
		panic(fmt.Sprintf("failed to generate dev session secret: %v", err))
	}
	_ = os.WriteFile(devSecretFile, []byte(hex.EncodeToString(secret)), 0600)
	sessionSecret = secret
	slog.Warn("SESSION_SECRET not set. Generated new dev secret and saved to " + devSecretFile)
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

func setSessionCookie(w http.ResponseWriter, signedID string) {
	isProd := os.Getenv("VERCEL") == "1" || os.Getenv("ENV") == "production"
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signedID,
		MaxAge:   sessionMaxAge, // MaxAge preferred over Expires: avoids client clock skew
		Path:     "/",
		HttpOnly: true,
		Secure:   isProd,
		SameSite: http.SameSiteLaxMode,
	})
}

func getSessionID(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		if id, ok := verifyID(cookie.Value); ok {
			// Sliding refresh: extend the cookie on every valid request so active
			// users never hit an unexpected expiry mid-session.
			setSessionCookie(w, cookie.Value)
			return id
		}
	}

	newID := uuid.New().String()
	signedID := signID(newID)
	setSessionCookie(w, signedID)
	return newID
}

