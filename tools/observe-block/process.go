package main

import (
	"bytes"
	"context"
	"errors"
	"io"
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
	buffer      bytes.Buffer
	limit       int
	observed    int64
	exceeded    bool
	retain      bool
	cancel      context.CancelFunc
	destination io.Writer
	writeFailed bool
}

func (w *boundedOutput) Write(raw []byte) (int, error) {
	w.observed += int64(len(raw))
	if w.observed > int64(w.limit) {
		w.exceeded = true
		w.cancel()
		return 0, errors.New("output limit exceeded")
	}
	if w.destination != nil {
		n, err := w.destination.Write(raw)
		if err != nil || n != len(raw) {
			w.writeFailed = true
			w.cancel()
			if err == nil {
				err = io.ErrShortWrite
			}
		}
		return n, err
	}
	if w.retain {
		return w.buffer.Write(raw)
	}
	return len(raw), nil
}

func runProcess(parent context.Context, path string, args []string, limit int, timeout time.Duration) processResult {
	return runProcessOutput(parent, path, args, limit, timeout, nil)
}

// Keep even file destinations behind boundedOutput. Giving exec an *os.File
// directly would bypass Write and its cap. Run still joins both stream copies
// before the caller reads or closes the destination; no file bytes are retained
// in the returned process result.
func runProcessOutput(parent context.Context, path string, args []string, limit int, timeout time.Duration, destination io.Writer) processResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	out := &boundedOutput{limit: limit, retain: destination == nil, destination: destination, cancel: cancel}
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
	case ctx.Err() == context.DeadlineExceeded:
		r.category, r.code = "timeout", 2
	case out.writeFailed:
		r.category, r.code = "input_unavailable", 70
	case ctx.Err() != nil:
		r.category, r.code = "timeout", 2
	case cmd.Process == nil:
		r.category, r.code = "process_unavailable", 70
	case err != nil || r.ExitCode == nil || *r.ExitCode != 0:
		r.category, r.code = "process_failure", 2
	}
	return r
}
