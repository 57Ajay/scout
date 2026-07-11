package server

import (
	"context"
	"net/http"

	"github.com/57ajay/scout/internal/approval"
	"github.com/57ajay/scout/internal/audit"
	"github.com/57ajay/scout/internal/policy"
)

// approveOrRun applies a policy decision to a non-streaming operation. On allow
// it runs immediately; on ask it parks an approval (waiting unless wait=false);
// on deny it rejects. run performs the operation and reports success.
func (s *Server) approveOrRun(
	w http.ResponseWriter, r *http.Request,
	kind, display, cwd string, params map[string]string,
	decision policy.Decision, ip string, wait bool,
	run func() (any, bool),
) {
	switch decision.Action {
	case policy.Deny:
		s.audit.Write(audit.Entry{IP: ip, Kind: kind, Command: display, Decision: "deny", Status: "blocked", Note: decision.Reason})
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "error": "denied by policy", "reason": decision.Reason, "decision": "deny",
		})

	case policy.Ask:
		execFn := func() (any, bool) {
			res, ok := run()
			s.audit.Write(audit.Entry{IP: ip, Kind: kind, Command: display, Decision: "ask", Status: "ran_after_approval"})
			return res, ok
		}
		a := s.approvals.Create(kind, display, cwd, decision.Reason, decision.Source, ip, params, execFn)
		s.audit.Write(audit.Entry{IP: ip, Kind: kind, Command: display, Decision: "ask", Status: "pending", ApprovalID: a.ID, Note: decision.Reason})

		if !wait {
			writePending(w, a, "poll the approval id, or approve it in the dashboard")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Approvals.WaitTimeout.Std())
		defer cancel()
		resolved := s.approvals.Wait(ctx, a.ID)
		switch resolved.Status {
		case approval.Completed:
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "approved": true, "approval_id": a.ID, "result": resolved.Result})
		case approval.Failed:
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "approved": true, "approval_id": a.ID, "result": resolved.Result})
		case approval.Denied:
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "denied": true, "approval_id": a.ID, "error": "denied by human", "reason": decision.Reason})
		default:
			writePending(w, a, "approval still pending after wait window; keep polling the approval id")
		}

	default: // allow
		res, ok := run()
		s.audit.Write(audit.Entry{IP: ip, Kind: kind, Command: display, Decision: "allow", Status: "ran"})
		status := http.StatusOK
		if !ok {
			status = http.StatusOK // operation-level failure still returns 200 with ok:false
		}
		writeJSON(w, status, map[string]any{"ok": ok, "result": res})
	}
}

func wantWait(r *http.Request) bool {
	if r.URL.Query().Has("wait") {
		return queryBool(r, "wait")
	}
	return true
}
