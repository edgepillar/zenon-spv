package main

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

type processResult struct {
	observation
	stdout   []byte
	category string
	code     int
}

// exec copies each stream through its own goroutine and joins both before Run
// returns. The buffers are never shared between streams or read before joining.
// Do not embed bytes.Buffer: its promoted ReadFrom method lets io.Copy bypass
// Write, disabling the cap and retaining supposedly discarded diagnostics.
type boundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	observed int64
	exceeded bool
	retain   bool
	cancel   context.CancelFunc
}

func (w *boundedOutput) Write(raw []byte) (int, error) {
	w.observed += int64(len(raw))
	if w.observed > int64(w.limit) {
		w.exceeded = true
		w.cancel()
		return 0, errors.New("output limit exceeded")
	}
	if w.retain {
		return w.buffer.Write(raw)
	}
	return len(raw), nil
}

func runProcess(parent context.Context, path string, args []string, limit int, timeout time.Duration) processResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	out := &boundedOutput{limit: limit, retain: true, cancel: cancel}
	diagnostics := &boundedOutput{limit: 16 << 10, cancel: cancel}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, diagnostics, time.Second
	started := time.Now()
	err := cmd.Run()
	r := processResult{observation: observation{ElapsedNS: time.Since(started).Nanoseconds(), StdoutBytes: out.observed, StderrBytes: diagnostics.observed}, stdout: out.buffer.Bytes()}
	if cmd.ProcessState != nil {
		status := int64(cmd.ProcessState.ExitCode())
		r.ExitCode = &status
	}
	switch {
	case out.exceeded || diagnostics.exceeded:
		r.category, r.code = "output_limit", 2
	case parent.Err() != nil:
		r.category, r.code = "cancelled", 2
	case ctx.Err() != nil:
		r.category, r.code = "timeout", 2
	case cmd.Process == nil:
		r.category, r.code = "process_unavailable", 70
	case err != nil || r.ExitCode == nil || *r.ExitCode != 0:
		r.category, r.code = "process_failure", 2
	}
	return r
}
