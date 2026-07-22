// Package audit records every decision and operation to a JSONL file and an
// in-memory ring buffer (for the dashboard/API). Tokens are never logged.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Entry is one audit record.
type Entry struct {
	Time       string `json:"time"`
	ID         string `json:"id"`
	IP         string `json:"ip,omitempty"`
	Kind       string `json:"kind"`               // exec | exec_stream | fs_read | fs_write | fs_edit | proc_start | approval | ...
	Command    string `json:"command,omitempty"`  // command or path
	Decision   string `json:"decision,omitempty"` // allow | ask | deny
	Status     string `json:"status,omitempty"`   // ran | blocked | pending | completed | denied | error
	ExitCode   *int   `json:"exit_code,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Log is the audit sink.
type Log struct {
	mu   sync.Mutex
	file *os.File
	mem  []Entry
	max  int
	seq  int64
}

// New opens (or creates) the audit file if path != "" and keeps up to max
// entries in memory.
func New(path string, max int) (*Log, error) {
	l := &Log{max: max}
	if path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		l.file = f
	}
	return l, nil
}

// Write records an entry. It stamps the time and a monotonic id if unset.
func (l *Log) Write(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.ID == "" {
		l.seq++
		e.ID = "ev_" + itoa(l.seq)
	}
	if l.file != nil {
		if b, err := json.Marshal(e); err == nil {
			l.file.Write(append(b, '\n'))
		}
	}
	l.mem = append(l.mem, e)
	if len(l.mem) > l.max {
		l.mem = l.mem[len(l.mem)-l.max:]
	}
}

// Recent returns up to n most-recent entries, newest first.
func (l *Log) Recent(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.mem) {
		n = len(l.mem)
	}
	out := make([]Entry, 0, n)
	for i := len(l.mem) - 1; i >= len(l.mem)-n; i-- {
		out = append(out, l.mem[i])
	}
	return out
}

// Close closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
