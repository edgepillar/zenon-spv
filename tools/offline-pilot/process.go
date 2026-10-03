package main

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

const testProcessWaitDelay = 2 * time.Second

// The command owns stdout copying, so WaitDelay can close a pipe inherited by
// an unrelated descendant. The collector consumes that copy concurrently; its
// pipe is closed only after Wait has joined command I/O. Never Wait concurrently
// with a caller-read StdoutPipe: that can truncate legitimate trailing events.
// This bounds command/stream settlement, not the lifetime of descendants or
// preflight/post-run filesystem reads.
func runTestProcess(parent context.Context, path string, args, env []string, readEvents func(io.Reader) error) (bool, *string) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	reader, writer := io.Pipe()
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env, cmd.Stdout, cmd.Stderr, cmd.WaitDelay = env, writer, io.Discard, testProcessWaitDelay
	if cmd.Start() != nil {
		return false, errorCategory("test_start")
	}
	joined := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		_ = writer.Close()
		joined <- err
	}()
	readErr := readEvents(reader)
	if readErr != nil {
		cancel()
		// A rejected collector must also release a copy goroutine blocked on
		// writing into this pipe before command settlement can be joined.
		_ = reader.Close()
	}
	waitErr := <-joined
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return false, errorCategory("test_timeout")
	case readErr != nil:
		return false, errorCategory("test_stream")
	case ctx.Err() != nil:
		return false, errorCategory("test_timeout")
	case waitErr != nil:
		return false, errorCategory("test_process")
	}
	return true, nil
}
