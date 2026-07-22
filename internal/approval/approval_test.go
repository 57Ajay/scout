package approval

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestApproveRunsAndAttachesResult(t *testing.T) {
	s := New(time.Hour, nil)
	ran := false
	a := s.Create("exec", "echo hi", "/tmp", "why", "builtin", "1.2.3.4", nil, func() (any, bool) {
		ran = true
		return map[string]string{"stdout": "hi"}, true
	})
	if a.Status != Pending {
		t.Fatalf("expected pending, got %s", a.Status)
	}
	resolved, ok := s.Approve(a.ID, "human")
	if !ok || !ran {
		t.Fatalf("approve failed ok=%v ran=%v", ok, ran)
	}
	if resolved.Status != Completed {
		t.Errorf("expected completed, got %s", resolved.Status)
	}
	if resolved.Result == nil {
		t.Error("expected result attached")
	}
}

func TestDenyDoesNotRun(t *testing.T) {
	s := New(time.Hour, nil)
	ran := false
	a := s.Create("exec", "rm -rf /", "/", "danger", "builtin", "", nil, func() (any, bool) {
		ran = true
		return nil, true
	})
	if _, ok := s.Deny(a.ID, "human"); !ok {
		t.Fatal("deny failed")
	}
	if ran {
		t.Error("denied command must not run")
	}
	if a.Status != Denied {
		t.Errorf("expected denied, got %s", a.Status)
	}
}

// Concurrent approve/deny on the same approvals must resolve each exactly once,
// run its execFn at most once, and never panic (double channel close).
func TestConcurrentResolveIsSafe(t *testing.T) {
	s := New(time.Hour, nil)
	const n = 50
	ids := make([]string, n)
	var runCounts [n]int32
	for i := 0; i < n; i++ {
		idx := i
		a := s.Create("exec", "cmd", "/", "r", "builtin", "", nil, func() (any, bool) {
			atomic.AddInt32(&runCounts[idx], 1)
			return "done", true
		})
		ids[i] = a.ID
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		id := ids[i]
		for c := 0; c < 8; c++ {
			wg.Add(2)
			go func() { defer wg.Done(); s.Approve(id, "a") }()
			go func() { defer wg.Done(); s.Deny(id, "d") }()
		}
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if rc := atomic.LoadInt32(&runCounts[i]); rc > 1 {
			t.Errorf("approval %d ran %d times (want <=1)", i, rc)
		}
		a, _ := s.Get(ids[i])
		if a.Status != Completed && a.Status != Denied {
			t.Errorf("approval %d unresolved: %s", i, a.Status)
		}
	}
}

// Wait must return promptly once an approval is resolved from another goroutine.
func TestWaitUnblocksOnResolve(t *testing.T) {
	s := New(time.Hour, nil)
	a := s.Create("exec", "cmd", "/", "r", "builtin", "", nil, func() (any, bool) { return "ok", true })
	done := make(chan Status, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		res := s.Wait(ctx, a.ID)
		done <- res.Status
	}()
	time.Sleep(50 * time.Millisecond)
	s.Approve(a.ID, "human")
	select {
	case st := <-done:
		if st != Completed {
			t.Errorf("expected completed, got %s", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not unblock after approve")
	}
}
