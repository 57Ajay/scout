package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/57ajay/scout/internal/approval"
	"github.com/57ajay/scout/internal/audit"
	"github.com/57ajay/scout/internal/executor"
	"github.com/57ajay/scout/internal/policy"
)

type execReq struct {
	Command string            `json:"command"`
	Cmd     string            `json:"cmd"` // alias for command
	Cwd     string            `json:"cwd"`
	Env     map[string]string `json:"env"`
	Timeout string            `json:"timeout"`
	Stream  bool              `json:"stream"`
	Wait    *bool             `json:"wait"`
	Session string            `json:"session"`
}

func (s *Server) parseExecReq(r *http.Request) (execReq, error) {
	var req execReq
	if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "" {
		ct := r.Header.Get("Content-Type")
		if len(ct) >= 16 && ct[:16] == "application/json" {
			dec := json.NewDecoder(r.Body)
			if err := dec.Decode(&req); err != nil {
				return req, err
			}
		}
	}
	// Query params override / fill in (so POST?stream=true works too).
	q := r.URL.Query()
	if v := q.Get("command"); v != "" {
		req.Command = v
	}
	if v := q.Get("cmd"); v != "" {
		req.Cmd = v
	}
	if v := q.Get("cwd"); v != "" {
		req.Cwd = v
	}
	if v := q.Get("timeout"); v != "" {
		req.Timeout = v
	}
	if v := q.Get("session"); v != "" {
		req.Session = v
	}
	if q.Has("stream") {
		req.Stream = queryBool(r, "stream")
	}
	if q.Has("wait") {
		b := queryBool(r, "wait")
		req.Wait = &b
	}
	if req.Command == "" {
		req.Command = req.Cmd
	}
	return req, nil
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	req, err := s.parseExecReq(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Command == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "missing 'cmd' (or 'command') parameter",
			"hint":  "GET /api/exec?token=...&cmd=ls%20-la  |  POST /api/exec {\"command\":\"...\"}",
		})
		return
	}

	// Session defaults for cwd/env.
	env := req.Env
	if req.Session != "" {
		st := s.sessions.get(req.Session)
		if req.Cwd == "" && st.cwd != "" {
			req.Cwd = st.cwd
		}
		if len(st.env) > 0 {
			merged := map[string]string{}
			for k, v := range st.env {
				merged[k] = v
			}
			for k, v := range env {
				merged[k] = v
			}
			env = merged
		}
	}

	cwd, err := s.resolveCwd(req.Cwd)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Session != "" {
		s.sessions.update(req.Session, cwd, req.Env)
	}

	timeout := s.commandTimeout(req.Timeout)
	ip := clientIP(r)
	decision := s.policy.Evaluate(req.Command)

	switch decision.Action {
	case policy.Deny:
		s.audit.Write(audit.Entry{IP: ip, Kind: "exec", Command: req.Command, Decision: "deny", Status: "blocked", Note: decision.Reason})
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":       false,
			"error":    "command denied by policy",
			"reason":   decision.Reason,
			"decision": "deny",
			"command":  req.Command,
		})
		return

	case policy.Ask:
		s.handleExecApproval(w, r, req, cwd, env, timeout, decision, ip)
		return
	}

	// ---- allow ----
	if req.Stream {
		s.audit.Write(audit.Entry{IP: ip, Kind: "exec_stream", Command: req.Command, Decision: "allow", Status: "ran"})
		s.streamExec(w, r, req.Command, cwd, env, timeout)
		return
	}
	res := s.exec.Run(r.Context(), req.Command, cwd, env, timeout)
	ec := res.ExitCode
	s.audit.Write(audit.Entry{IP: ip, Kind: "exec", Command: req.Command, Decision: "allow", Status: "ran", ExitCode: &ec, DurationMS: res.DurationMS})
	writeJSON(w, http.StatusOK, res)
}

// handleExecApproval parks the command and either waits for a decision or
// returns a pending handle.
func (s *Server) handleExecApproval(w http.ResponseWriter, r *http.Request, req execReq, cwd string, env map[string]string, timeout time.Duration, decision policy.Decision, ip string) {
	execFn := func() (any, bool) {
		res := s.exec.Run(context.Background(), req.Command, cwd, env, timeout)
		ec := res.ExitCode
		s.audit.Write(audit.Entry{IP: ip, Kind: "exec", Command: req.Command, Decision: "ask", Status: "ran_after_approval", ExitCode: &ec, DurationMS: res.DurationMS})
		return res, res.Error == ""
	}
	a := s.approvals.Create("exec", req.Command, cwd, decision.Reason, decision.Source, ip,
		map[string]string{"timeout": timeout.String()}, execFn)
	s.audit.Write(audit.Entry{IP: ip, Kind: "exec", Command: req.Command, Decision: "ask", Status: "pending", ApprovalID: a.ID, Note: decision.Reason})

	// Streaming and approval don't compose (execution happens on approve), so
	// respond with the pending handle even if stream was requested.
	wait := true
	if req.Wait != nil {
		wait = *req.Wait
	}
	if !wait {
		writePending(w, a, "poll the approval id, or approve it in the dashboard")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Approvals.WaitTimeout.Std())
	defer cancel()
	resolved := s.approvals.Wait(ctx, a.ID)

	switch resolved.Status {
	case approval.Completed, approval.Failed:
		if res, ok := resolved.Result.(executor.Result); ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":          res.OK,
				"approved":    true,
				"approval_id": a.ID,
				"result":      res,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "approved": true, "approval_id": a.ID, "result": resolved.Result})
	case approval.Denied:
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "approved": false, "denied": true,
			"approval_id": a.ID, "error": "command denied by human", "reason": decision.Reason,
		})
	default:
		// still pending — hand back a poll handle
		writePending(w, a, "approval still pending after wait window; keep polling the approval id")
	}
}

func writePending(w http.ResponseWriter, a *approval.Approval, hint string) {
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":          false,
		"status":      "pending_approval",
		"approval_id": a.ID,
		"decision":    "ask",
		"reason":      a.Reason,
		"command":     a.Command,
		"poll":        "/api/approvals/" + a.ID,
		"hint":        hint,
	})
}

// streamExec streams command output as newline-delimited JSON events.
func (s *Server) streamExec(w http.ResponseWriter, r *http.Request, command, cwd string, env map[string]string, timeout time.Duration) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	s.exec.RunStream(r.Context(), command, cwd, env, timeout, func(ev executor.Event) {
		_ = enc.Encode(ev)
		flusher.Flush()
	})
}
