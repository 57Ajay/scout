package server

import (
	_ "embed"
	"net/http"
)

//go:embed dashboard.html
var dashboardHTML string

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// The page itself is public HTML; all data calls from it carry the token
	// taken from the URL query, and the API enforces auth.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(dashboardHTML))
}
