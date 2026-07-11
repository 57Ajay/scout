package server

import (
	"encoding/json"
	"net/http"

	"github.com/57ajay/scout/internal/audit"
	"github.com/57ajay/scout/internal/policy"
)

type procStartReq struct {
	Command string            `json:"command"`
	Cmd     string            `json:"cmd"`
	Cwd     string            `json:"cwd"`
	Env     map[string]string `json:"env"`
}

// POST /api/proc/start
func (s *Server) handleProcStart(w http.ResponseWriter, r *http.Request) {
	var req procStartReq
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Command == "" {
		req.Command = req.Cmd
	}
	if v := r.URL.Query().Get("cmd"); v != "" {
		req.Command = v
	}
	if v := r.URL.Query().Get("cwd"); v != "" {
		req.Cwd = v
	}
	if req.Command == "" {
		writeErr(w, http.StatusBadRequest, "missing 'command'")
		return
	}
	cwd, err := s.resolveCwd(req.Cwd)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ip := clientIP(r)
	decision := s.policy.Evaluate(req.Command)
	if decision.Action == policy.Deny {
		s.audit.Write(audit.Entry{IP: ip, Kind: "proc_start", Command: req.Command, Decision: "deny", Status: "blocked", Note: decision.Reason})
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "denied by policy", "reason": decision.Reason})
		return
	}
	if decision.Action == policy.Ask {
		s.approveOrRun(w, r, "proc_start", req.Command, cwd, map[string]string{"cwd": cwd}, decision, ip, wantWait(r), func() (any, bool) {
			snap, err := s.procs.Start(req.Command, cwd, req.Env)
			if err != nil {
				return map[string]string{"error": err.Error()}, false
			}
			return snap, true
		})
		return
	}
	snap, err := s.procs.Start(req.Command, cwd, req.Env)
	if err != nil {
		writeErr(w, http.StatusOK, err.Error())
		return
	}
	s.audit.Write(audit.Entry{IP: ip, Kind: "proc_start", Command: req.Command, Decision: "allow", Status: "started", Note: snap.ID})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "process": snap})
}

// GET /api/proc
func (s *Server) handleProcList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "processes": s.procs.List()})
}

// GET /api/proc/{id}
func (s *Server) handleProcGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	snap, ok := s.procs.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "no such process")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "process": snap})
}

// GET /api/proc/{id}/logs?since=..&stream=true
func (s *Server) handleProcLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	since := int64(queryInt(r, "since", 0))

	if queryBool(r, "stream") {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeErr(w, http.StatusInternalServerError, "streaming unsupported")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		found := s.procs.Stream(r.Context(), id, since, func(b []byte) {
			_, _ = w.Write(b)
			flusher.Flush()
		})
		if !found {
			writeErr(w, http.StatusNotFound, "no such process")
		}
		return
	}

	res, ok := s.procs.Logs(id, since)
	if !ok {
		writeErr(w, http.StatusNotFound, "no such process")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "logs": res})
}

// POST /api/proc/{id}/stop
func (s *Server) handleProcStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	snap, ok := s.procs.Stop(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "no such process")
		return
	}
	s.audit.Write(audit.Entry{IP: clientIP(r), Kind: "proc_stop", Command: snap.Command, Status: "stopped", Note: id})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "process": snap})
}

// POST /api/proc/{id}/remove
func (s *Server) handleProcRemove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.procs.Remove(id) {
		writeErr(w, http.StatusConflict, "process not found or still running")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": id})
}
