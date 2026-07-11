// Package approval implements the human-in-the-loop queue. When the policy
// engine returns "ask", the server parks the operation here. A human approves
// or denies it (via the dashboard or API). On approval the operation executes
// and its result is attached, so a waiting agent gets the result in one call
// and a polling agent can fetch it later.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type Status string

const (
	Pending   Status = "pending"
	Completed Status = "completed" // approved and executed
	Denied    Status = "denied"
	Expired   Status = "expired"
	Failed    Status = "failed" // approved but execution errored
)

// ExecFunc runs the approved operation and returns its result (marshalled to
// JSON by the caller). ok reports whether execution succeeded.
type ExecFunc func() (result any, ok bool)

// Approval is one parked operation awaiting a human decision.
type Approval struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"` // exec | fs
	Command   string            `json:"command,omitempty"`
	Cwd       string            `json:"cwd,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
	Reason    string            `json:"reason"`
	Source    string            `json:"source"` // which policy rule fired
	SourceIP  string            `json:"source_ip,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	Status    Status            `json:"status"`
	DecidedAt *time.Time        `json:"decided_at,omitempty"`
	DecidedBy string            `json:"decided_by,omitempty"`
	Result    any               `json:"result,omitempty"`

	exec      ExecFunc
	resolved  chan struct{}
	resolving bool // set under lock once a decision path claims this approval
}

// Store holds pending and resolved approvals.
type Store struct {
	mu    sync.Mutex
	items map[string]*Approval
	order []string
	ttl   time.Duration
	// onCreate is called (in a goroutine) when a new approval is parked.
	onCreate func(*Approval)
}

// New builds a Store. ttl is how long a pending approval lives before expiring.
func New(ttl time.Duration, onCreate func(*Approval)) *Store {
	s := &Store{
		items:    make(map[string]*Approval),
		ttl:      ttl,
		onCreate: onCreate,
	}
	go s.reaper()
	return s
}

// Create parks a new operation and returns it.
func (s *Store) Create(kind, command, cwd, reason, source, ip string, params map[string]string, exec ExecFunc) *Approval {
	a := &Approval{
		ID:        "ap_" + randID(),
		Kind:      kind,
		Command:   command,
		Cwd:       cwd,
		Params:    params,
		Reason:    reason,
		Source:    source,
		SourceIP:  ip,
		CreatedAt: time.Now(),
		Status:    Pending,
		exec:      exec,
		resolved:  make(chan struct{}),
	}
	s.mu.Lock()
	s.items[a.ID] = a
	s.order = append(s.order, a.ID)
	s.mu.Unlock()

	if s.onCreate != nil {
		go s.onCreate(a)
	}
	return a
}

// Get returns an approval by ID.
func (s *Store) Get(id string) (*Approval, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.items[id]
	return a, ok
}

// List returns approvals, optionally filtered by status, newest first.
func (s *Store) List(status Status) []*Approval {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Approval, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		a := s.items[s.order[i]]
		if a == nil {
			continue
		}
		if status == "" || a.Status == status {
			out = append(out, a)
		}
	}
	return out
}

// Approve executes the parked operation and marks it completed (or failed).
func (s *Store) Approve(id, by string) (*Approval, bool) {
	s.mu.Lock()
	a, ok := s.items[id]
	if !ok || a.Status != Pending || a.resolving {
		s.mu.Unlock()
		return a, false
	}
	// Claim it under the lock so a concurrent approve/deny or the TTL reaper
	// cannot also resolve (and double-close) it while execFn runs.
	a.resolving = true
	now := time.Now()
	a.DecidedAt = &now
	a.DecidedBy = by
	execFn := a.exec
	s.mu.Unlock()

	var result any
	okExec := true
	if execFn != nil {
		result, okExec = execFn()
	}

	s.mu.Lock()
	a.Result = result
	if okExec {
		a.Status = Completed
	} else {
		a.Status = Failed
	}
	close(a.resolved)
	s.mu.Unlock()
	return a, true
}

// Deny marks the parked operation denied.
func (s *Store) Deny(id, by string) (*Approval, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.items[id]
	if !ok || a.Status != Pending || a.resolving {
		return a, false
	}
	a.resolving = true
	now := time.Now()
	a.DecidedAt = &now
	a.DecidedBy = by
	a.Status = Denied
	close(a.resolved)
	return a, true
}

// Wait blocks until the approval is resolved or ctx is done. It returns the
// (possibly still pending) approval.
func (s *Store) Wait(ctx context.Context, id string) *Approval {
	s.mu.Lock()
	a, ok := s.items[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	ch := a.resolved
	s.mu.Unlock()

	select {
	case <-ch:
	case <-ctx.Done():
	}
	return a
}

// PendingCount returns the number of pending approvals.
func (s *Store) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.items {
		if a.Status == Pending {
			n++
		}
	}
	return n
}

func (s *Store) reaper() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-s.ttl)
		s.mu.Lock()
		for _, a := range s.items {
			if a.Status == Pending && !a.resolving && a.CreatedAt.Before(cutoff) {
				a.resolving = true
				a.Status = Expired
				close(a.resolved)
			}
		}
		s.mu.Unlock()
	}
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
