package controllers

import (
	"database/sql"
	"net/http"
)

func (c Controller) Protected(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("success."))
	}
}
