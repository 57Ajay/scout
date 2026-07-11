package server

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/57ajay/scout/internal/audit"
	"github.com/57ajay/scout/internal/fsops"
)

// GET /api/fs/read?path=...&start=..&end=..&stream=true
func (s *Server) handleFSRead(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "missing 'path'")
		return
	}
	abs, err := s.fs.Resolve(path, s.cfg.Exec.WorkingDir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ip := clientIP(r)
	decision := s.policy.EvaluatePath("read", abs)
	if decision.Action == "deny" {
		s.audit.Write(audit.Entry{IP: ip, Kind: "fs_read", Command: abs, Decision: "deny", Status: "blocked", Note: decision.Reason})
		writeErr(w, http.StatusForbidden, "read denied by policy: "+decision.Reason)
		return
	}

	start := queryInt(r, "start", 0)
	end := queryInt(r, "end", 0)

	// Streaming read for large files.
	if queryBool(r, "stream") && decision.Action == "allow" {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeErr(w, http.StatusInternalServerError, "streaming unsupported")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		fw := &flushWriter{w: w, f: flusher}
		if _, err := s.fs.Stream(abs, start, end, fw); err != nil {
			// best-effort trailer; headers already sent
			_, _ = io.WriteString(w, "\n[scout: stream error: "+err.Error()+"]\n")
		}
		s.audit.Write(audit.Entry{IP: ip, Kind: "fs_read", Command: abs, Decision: "allow", Status: "streamed"})
		return
	}

	maxBytes := s.cfg.Limits.MaxOutputBytes
	if decision.Action == "ask" {
		// Reading a protected file: route through approval.
		s.approveOrRun(w, r, "fs_read", abs, "", map[string]string{"path": abs}, decision, ip, wantWait(r), func() (any, bool) {
			res, err := s.fs.Read(abs, start, end, maxBytes)
			if err != nil {
				return map[string]string{"error": err.Error()}, false
			}
			return res, true
		})
		return
	}

	res, err := s.fs.Read(abs, start, end, maxBytes)
	if err != nil {
		writeErr(w, http.StatusOK, err.Error())
		return
	}
	s.audit.Write(audit.Entry{IP: ip, Kind: "fs_read", Command: abs, Decision: "allow", Status: "ran"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": res})
}

type fsWriteReq struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode"`   // overwrite | append | create
	Base64  bool   `json:"base64"` // content is base64-encoded
	Mkdirs  bool   `json:"mkdirs"`
}

// POST /api/fs/write
func (s *Server) handleFSWrite(w http.ResponseWriter, r *http.Request) {
	var req fsWriteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.Path == "" {
		writeErr(w, http.StatusBadRequest, "missing 'path'")
		return
	}
	abs, err := s.fs.Resolve(req.Path, s.cfg.Exec.WorkingDir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := fsops.WriteMode(req.Mode)
	if mode == "" {
		mode = fsops.Overwrite
	}
	ip := clientIP(r)
	decision := s.policy.EvaluatePath("write", abs)
	s.approveOrRun(w, r, "fs_write", abs, "", map[string]string{"path": abs, "mode": string(mode)}, decision, ip, wantWait(r), func() (any, bool) {
		res, err := s.fs.Write(abs, req.Content, mode, req.Mkdirs, req.Base64)
		if err != nil {
			return map[string]string{"error": err.Error()}, false
		}
		return res, true
	})
}

type fsEditReq struct {
	Path  string         `json:"path"`
	Edits []fsops.EditOp `json:"edits"`
}

// POST /api/fs/edit
func (s *Server) handleFSEdit(w http.ResponseWriter, r *http.Request) {
	var req fsEditReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.Path == "" || len(req.Edits) == 0 {
		writeErr(w, http.StatusBadRequest, "require 'path' and at least one edit")
		return
	}
	abs, err := s.fs.Resolve(req.Path, s.cfg.Exec.WorkingDir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ip := clientIP(r)
	decision := s.policy.EvaluatePath("edit", abs)
	s.approveOrRun(w, r, "fs_edit", abs, "", map[string]string{"path": abs}, decision, ip, wantWait(r), func() (any, bool) {
		res, err := s.fs.Edit(abs, req.Edits)
		if err != nil {
			return map[string]string{"error": err.Error()}, false
		}
		return res, true
	})
}

// GET /api/fs/list?path=..&recursive=true&depth=2
func (s *Server) handleFSList(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "."
	}
	abs, err := s.fs.Resolve(path, s.cfg.Exec.WorkingDir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := s.fs.List(abs, queryBool(r, "recursive"), queryInt(r, "depth", 0))
	if err != nil {
		writeErr(w, http.StatusOK, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": abs, "entries": entries, "count": len(entries)})
}

// GET /api/fs/stat?path=..
func (s *Server) handleFSStat(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "missing 'path'")
		return
	}
	abs, err := s.fs.Resolve(path, s.cfg.Exec.WorkingDir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	info, err := s.fs.Stat(abs)
	if err != nil {
		writeErr(w, http.StatusOK, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": info})
}

type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	fw.f.Flush()
	return n, err
}
