package server

import (
	"net/http"

	"github.com/57ajay/scout/internal/approval"
	"github.com/57ajay/scout/internal/audit"
)

// GET /api/approvals?status=pending
func (s *Server) handleApprovalsList(w http.ResponseWriter, r *http.Request) {
	status := approval.Status(r.URL.Query().Get("status"))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"approvals": s.approvals.List(status),
		"pending":   s.approvals.PendingCount(),
	})
}

// GET /api/approvals/{id}
func (s *Server) handleApprovalGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.approvals.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "no such approval")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "approval": a})
}

// POST /api/approvals/{id}/approve
func (s *Server) handleApprovalApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	by := r.URL.Query().Get("by")
	if by == "" {
		by = "human@" + clientIP(r)
	}
	a, ok := s.approvals.Approve(id, by)
	if !ok {
		if a == nil {
			writeErr(w, http.StatusNotFound, "no such approval")
			return
		}
		writeErr(w, http.StatusConflict, "approval is not pending (status: "+string(a.Status)+")")
		return
	}
	s.audit.Write(audit.Entry{IP: clientIP(r), Kind: "approval", Command: a.Command, Decision: "ask", Status: "approved", ApprovalID: id, Note: "by " + by})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "approval": a})
}

// POST /api/approvals/{id}/deny
func (s *Server) handleApprovalDeny(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	by := r.URL.Query().Get("by")
	if by == "" {
		by = "human@" + clientIP(r)
	}
	a, ok := s.approvals.Deny(id, by)
	if !ok {
		if a == nil {
			writeErr(w, http.StatusNotFound, "no such approval")
			return
		}
		writeErr(w, http.StatusConflict, "approval is not pending (status: "+string(a.Status)+")")
		return
	}
	s.audit.Write(audit.Entry{IP: clientIP(r), Kind: "approval", Command: a.Command, Decision: "ask", Status: "denied", ApprovalID: id, Note: "by " + by})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "approval": a})
}
