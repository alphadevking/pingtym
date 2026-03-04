package handler

import (
	"net/http"
	"pingtym/pkg/app"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	app.Handler(w, r)
}
