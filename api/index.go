package handler

import (
	"net/http"
	"pingtym/internal/app"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	app.Handler(w, r)
}
