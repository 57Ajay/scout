// Package executor runs shell commands with full shell power (bash -lc by
// default) and returns either a buffered result or a stream of output events.
package executor

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Result is the buffered outcome of a command.
type Result struct {
	OK              bool   `json:"ok"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr,omitempty"`
	ExitCode        int    `json:"exit_code"`
	Cwd             string `json:"cwd"`
	Command         string `json:"command"`
	Duration        string `json:"duration"`
	DurationMS      int64  `json:"duration_ms"`
	TimedOut        bool   `json:"timed_out,omitempty"`
	TruncatedStdout bool   `json:"truncated_stdout,omitempty"`
	TruncatedStderr bool   `json:"truncated_stderr,omitempty"`
	Error           string `json:"error,omitempty"`
}

// Event is a single streamed output event.
type Event struct {
	Type       string `json:"type"`                  // meta | stdout | stderr | exit | error
	Data       string `json:"data,omitempty"`        // for stdout/stderr/error
	ExitCode   int    `json:"exit_code,omitempty"`   // for exit
	Cwd        string `json:"cwd,omitempty"`         // for meta
	Command    string `json:"command,omitempty"`     // for meta
	TimedOut   bool   `json:"timed_out,omitempty"`   // for exit
	DurationMS int64  `json:"duration_ms,omitempty"` // for exit
}

// Executor runs commands with a configured shell and environment.
type Executor struct {
	shell          []string
	baseEnv        []string
	maxOutput      int
	defaultTimeout time.Duration
}

// New builds an Executor. shell is argv like ["/bin/bash","-lc"].
func New(shell []string, maxOutput int, defaultTimeout time.Duration) *Executor {
	return &Executor{
		shell:          shell,
		baseEnv:        os.Environ(),
		maxOutput:      maxOutput,
		defaultTimeout: defaultTimeout,
	}
}

// Shell returns the configured shell argv (for display).
func (e *Executor) Shell() []string { return append([]string(nil), e.shell...) }

func (e *Executor) buildCmd(ctx context.Context, command, cwd string, env map[string]string) *exec.Cmd {
	args := append(append([]string{}, e.shell[1:]...), command)
	cmd := exec.CommandContext(ctx, e.shell[0], args...)
	cmd.Dir = cwd
	cmd.Env = mergeEnv(e.baseEnv, env)
	// New process group so we can kill the whole tree (pipelines, children).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Ensure the group is signalled on context cancel/timeout.
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	return cmd
}

// Run executes a command and buffers its output.
func (e *Executor) Run(ctx context.Context, command, cwd string, env map[string]string, timeout time.Duration) Result {
	if timeout <= 0 {
		timeout = e.defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	cmd := e.buildCmd(ctx, command, cwd, env)

	var stdout, stderr bytes.Buffer
	lwOut := &limitedWriter{buf: &stdout, max: e.maxOutput}
	lwErr := &limitedWriter{buf: &stderr, max: e.maxOutput}
	cmd.Stdout = lwOut
	cmd.Stderr = lwErr

	err := cmd.Run()
	dur := time.Since(start)

	res := Result{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		Cwd:             cwd,
		Command:         command,
		Duration:        dur.String(),
		DurationMS:      dur.Milliseconds(),
		TruncatedStdout: lwOut.truncated,
		TruncatedStderr: lwErr.truncated,
	}

	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = 124
		res.Error = "command timed out"
		return res
	}

	res.ExitCode = exitCode(err, &res)
	res.OK = res.ExitCode == 0 && res.Error == ""
	return res
}

// RunStream executes a command and calls emit for each output event. It emits a
// leading "meta" event, interleaved "stdout"/"stderr" events, and a final
// "exit" event. emit must be safe to call from multiple goroutines? No — this
// serializes emits through a mutex, so emit need not be concurrency-safe.
func (e *Executor) RunStream(ctx context.Context, command, cwd string, env map[string]string, timeout time.Duration, emit func(Event)) {
	if timeout <= 0 {
		timeout = e.defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	cmd := e.buildCmd(ctx, command, cwd, env)

	var emitMu sync.Mutex
	safeEmit := func(ev Event) {
		emitMu.Lock()
		defer emitMu.Unlock()
		emit(ev)
	}

	safeEmit(Event{Type: "meta", Cwd: cwd, Command: command})

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		safeEmit(Event{Type: "error", Data: "stdout pipe: " + err.Error()})
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		safeEmit(Event{Type: "error", Data: "stderr pipe: " + err.Error()})
		return
	}

	if err := cmd.Start(); err != nil {
		safeEmit(Event{Type: "error", Data: "start: " + err.Error()})
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go pump(&wg, stdoutPipe, "stdout", safeEmit)
	go pump(&wg, stderrPipe, "stderr", safeEmit)
	wg.Wait()

	waitErr := cmd.Wait()
	dur := time.Since(start)

	exit := Event{Type: "exit", DurationMS: dur.Milliseconds()}
	if ctx.Err() == context.DeadlineExceeded {
		exit.TimedOut = true
		exit.ExitCode = 124
	} else {
		var r Result
		exit.ExitCode = exitCode(waitErr, &r)
		if r.Error != "" {
			safeEmit(Event{Type: "error", Data: r.Error})
		}
	}
	safeEmit(exit)
}

func pump(wg *sync.WaitGroup, r io.Reader, kind string, emit func(Event)) {
	defer wg.Done()
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			emit(Event{Type: kind, Data: string(buf[:n])})
		}
		if err != nil {
			return
		}
	}
}

func exitCode(err error, res *Result) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	// Non-run errors (binary missing, etc.)
	res.Error = err.Error()
	return -1
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
		if i := indexByte(kv, '='); i >= 0 {
			key = kv[:i]
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

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// limitedWriter caps how much output we buffer, recording whether truncation
// occurred.
type limitedWriter struct {
	buf       *bytes.Buffer
	max       int
	truncated bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.max - w.buf.Len()
	if remaining <= 0 {
		w.truncated = true
		return len(p), nil // discard, but report success so the process continues
	}
	if len(p) > remaining {
		w.buf.Write(p[:remaining])
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}
