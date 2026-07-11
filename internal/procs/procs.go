// Package procs manages long-running background processes (dev servers, log
// tails, port-forwards) started via the shell. It captures combined output in a
// bounded buffer, supports tailing by offset and live streaming, and can stop a
// process (and its whole group).
package procs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const defaultBufferCap = 2 * 1024 * 1024 // 2 MB retained per process

// Process is a tracked background process.
type Process struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	Cwd       string    `json:"cwd"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"` // running | exited | killed | error
	ExitCode  *int      `json:"exit_code,omitempty"`
	Error     string    `json:"error,omitempty"`

	mu       sync.Mutex
	buf      []byte
	dropped  int64
	subs     map[chan []byte]struct{}
	done     chan struct{}
	cmd      *exec.Cmd
	finished bool
}

// Snapshot is a JSON-friendly view of a process without internals.
type Snapshot struct {
	ID        string `json:"id"`
	Command   string `json:"command"`
	Cwd       string `json:"cwd"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
	Status    string `json:"status"`
	ExitCode  *int   `json:"exit_code,omitempty"`
	Error     string `json:"error,omitempty"`
	OutputLen int64  `json:"output_len"`
}

func (p *Process) snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Snapshot{
		ID:        p.ID,
		Command:   p.Command,
		Cwd:       p.Cwd,
		PID:       p.PID,
		StartedAt: p.StartedAt.UTC().Format(time.RFC3339),
		Status:    p.Status,
		ExitCode:  p.ExitCode,
		Error:     p.Error,
		OutputLen: p.dropped + int64(len(p.buf)),
	}
}

// Manager tracks background processes.
type Manager struct {
	mu      sync.Mutex
	procs   map[string]*Process
	order   []string
	shell   []string
	baseEnv []string
}

// New builds a Manager. shell is argv like ["/bin/bash","-lc"].
func New(shell []string) *Manager {
	return &Manager{
		procs:   make(map[string]*Process),
		shell:   shell,
		baseEnv: os.Environ(),
	}
}

// Start launches a background process and returns its snapshot.
func (m *Manager) Start(command, cwd string, env map[string]string) (Snapshot, error) {
	id := "proc_" + randID()
	args := append(append([]string{}, m.shell[1:]...), command)
	cmd := exec.Command(m.shell[0], args...)
	cmd.Dir = cwd
	cmd.Env = mergeEnv(m.baseEnv, env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	p := &Process{
		ID:        id,
		Command:   command,
		Cwd:       cwd,
		StartedAt: time.Now(),
		Status:    "running",
		subs:      make(map[chan []byte]struct{}),
		done:      make(chan struct{}),
		cmd:       cmd,
	}
	cmd.Stdout = writerFunc(p.append)
	cmd.Stderr = writerFunc(p.append)

	if err := cmd.Start(); err != nil {
		p.Status = "error"
		p.Error = err.Error()
		return p.snapshot(), err
	}
	p.PID = cmd.Process.Pid

	m.mu.Lock()
	m.procs[id] = p
	m.order = append(m.order, id)
	m.mu.Unlock()

	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.finished = true
		if p.Status == "running" {
			if err == nil {
				p.Status = "exited"
				code := 0
				p.ExitCode = &code
			} else if exitErr, ok := err.(*exec.ExitError); ok {
				p.Status = "exited"
				code := exitErr.ExitCode()
				p.ExitCode = &code
			} else {
				p.Status = "error"
				p.Error = err.Error()
			}
		}
		for ch := range p.subs {
			close(ch)
			delete(p.subs, ch)
		}
		close(p.done)
		p.mu.Unlock()
	}()

	return p.snapshot(), nil
}

func (p *Process) append(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf = append(p.buf, b...)
	if len(p.buf) > defaultBufferCap {
		over := len(p.buf) - defaultBufferCap
		p.buf = p.buf[over:]
		p.dropped += int64(over)
	}
	chunk := append([]byte(nil), b...)
	for ch := range p.subs {
		select {
		case ch <- chunk:
		default: // slow consumer: drop for that subscriber
		}
	}
}

// List returns snapshots of all tracked processes, newest last.
func (m *Manager) List() []Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Snapshot, 0, len(m.order))
	for _, id := range m.order {
		if p, ok := m.procs[id]; ok {
			out = append(out, p.snapshot())
		}
	}
	return out
}

// Get returns a process snapshot.
func (m *Manager) Get(id string) (Snapshot, bool) {
	m.mu.Lock()
	p, ok := m.procs[id]
	m.mu.Unlock()
	if !ok {
		return Snapshot{}, false
	}
	return p.snapshot(), true
}

// LogsResult is a tail of process output.
type LogsResult struct {
	Output   string `json:"output"`
	Offset   int64  `json:"offset"` // absolute offset of the end of Output
	Dropped  bool   `json:"dropped,omitempty"`
	Status   string `json:"status"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

// Logs returns output from absolute offset `since` to the current end.
func (m *Manager) Logs(id string, since int64) (LogsResult, bool) {
	m.mu.Lock()
	p, ok := m.procs[id]
	m.mu.Unlock()
	if !ok {
		return LogsResult{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	start := since - p.dropped
	dropped := false
	if start < 0 {
		start = 0
		dropped = true
	}
	if start > int64(len(p.buf)) {
		start = int64(len(p.buf))
	}
	out := string(p.buf[start:])
	return LogsResult{
		Output:   out,
		Offset:   p.dropped + int64(len(p.buf)),
		Dropped:  dropped,
		Status:   p.Status,
		ExitCode: p.ExitCode,
	}, true
}

// Stream sends live output chunks to `emit` until the process exits or ctx is
// done. It first replays buffered output from offset `since`.
func (m *Manager) Stream(ctx context.Context, id string, since int64, emit func([]byte)) bool {
	m.mu.Lock()
	p, ok := m.procs[id]
	m.mu.Unlock()
	if !ok {
		return false
	}

	p.mu.Lock()
	if p.finished {
		start := since - p.dropped
		if start < 0 {
			start = 0
		}
		if start < int64(len(p.buf)) {
			emit(append([]byte(nil), p.buf[start:]...))
		}
		p.mu.Unlock()
		return true
	}
	// replay backlog
	start := since - p.dropped
	if start < 0 {
		start = 0
	}
	if start < int64(len(p.buf)) {
		emit(append([]byte(nil), p.buf[start:]...))
	}
	ch := make(chan []byte, 64)
	p.subs[ch] = struct{}{}
	done := p.done
	p.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			p.mu.Lock()
			delete(p.subs, ch)
			p.mu.Unlock()
			return true
		case <-done:
			// drain any remaining buffered chunks
			for {
				select {
				case b, ok := <-ch:
					if !ok {
						return true
					}
					emit(b)
				default:
					return true
				}
			}
		case b, ok := <-ch:
			if !ok {
				return true
			}
			emit(b)
		}
	}
}

// Stop terminates a process (whole group) with SIGTERM, then SIGKILL.
func (m *Manager) Stop(id string) (Snapshot, bool) {
	m.mu.Lock()
	p, ok := m.procs[id]
	m.mu.Unlock()
	if !ok {
		return Snapshot{}, false
	}
	p.mu.Lock()
	running := !p.finished && p.cmd != nil && p.cmd.Process != nil
	pid := p.PID
	if running {
		p.Status = "killed"
	}
	p.mu.Unlock()

	if running {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
		go func() {
			time.Sleep(3 * time.Second)
			p.mu.Lock()
			fin := p.finished
			p.mu.Unlock()
			if !fin {
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
		}()
	}
	return p.snapshot(), true
}

// Remove deletes a finished process from tracking.
func (m *Manager) Remove(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.procs[id]
	if !ok {
		return false
	}
	p.mu.Lock()
	fin := p.finished
	p.mu.Unlock()
	if !fin {
		return false
	}
	delete(m.procs, id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	return true
}

type writerFunc func([]byte)

func (w writerFunc) Write(p []byte) (int, error) {
	w(p)
	return len(p), nil
}

func mergeEnv(base []string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return base
	}
	out := make([]string, 0, len(base)+len(overrides))
	seen := make(map[string]bool, len(overrides))
	for k := range overrides {
		seen[k] = true
	}
	for _, kv := range base {
		key := kv
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				key = kv[:i]
				break
			}
		}
		if !seen[key] {
			out = append(out, kv)
		}
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
