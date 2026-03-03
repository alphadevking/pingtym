package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

const sessionCookieName = "pingtym_session"

func getSessionID(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		return cookie.Value
	}

	// Create new session
	newID := uuid.New().String()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    newID,
		Expires:  time.Now().Add(365 * 24 * time.Hour), // 1 year persistence
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return newID
}
