package verify

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync/atomic"
)

const (
	// These are persistence limits, independent of the selected runtime tier.
	MaxStateFileBytes    int64 = 64 * 1024 * 1024
	MaxPersistedHeaders        = DefaultMaxHeaders + 1
	parallelStateLoadMin       = 1024
)

var (
	ErrStateFileTooLarge    = errors.New("state file exceeds byte limit")
	ErrInvalidRetainedState = errors.New("invalid retained state")
	// Allow at most one extra verification worker per process. A concurrent
	// load without the slot runs on its calling goroutine.
	stateLoadWorker = make(chan struct{}, 1)
)

// validateRetainedState detects corruption before save or resume. A truncated
// window cannot re-prove its evicted ancestry: its first header and the local
// anchor still require trusted provenance. Signatures do not elect producers.
// Only the loader may allow a worker, since its decoded window is private.
func (s HeaderState) validateRetainedState(allowParallel bool) error {
	if s.Genesis.HeaderHash.IsZero() || s.Capacity < 1 || s.Capacity > MaxPersistedHeaders ||
		len(s.RetainedWindow) > s.Capacity || s.RetainHeaders < 0 || s.RetainHeaders > MaxRetainHeaders ||
		(s.RetainHeaders != 0 && s.RetainHeaders != s.Capacity) {
		return fmt.Errorf("%w: anchor or capacity", ErrInvalidRetainedState)
	}
	if err := s.ValidateHeaderVersions(); err != nil {
		return err
	}
	var checkpoints []Checkpoint
	if s.Genesis.ChainID == MainnetChainID {
		checkpoints = MainnetCheckpoints()
	}
	count := len(s.RetainedWindow)
	if allowParallel && count >= parallelStateLoadMin && runtime.GOMAXPROCS(0) > 1 {
		select {
		case stateLoadWorker <- struct{}{}:
			defer func() { <-stateLoadWorker }()
			// The first failing header still decides the error. Stop the
			// suffix once the prefix fails, and join it before returning.
			middle := count / 2
			var stop atomic.Bool
			done := make(chan error, 1)
			go func() { done <- s.validateRetainedHeaders(middle, count, checkpoints, &stop) }()
			if err := s.validateRetainedHeaders(0, middle, checkpoints, nil); err != nil {
				stop.Store(true)
				<-done
				return err
			}
			return <-done
		default:
		}
	}
	return s.validateRetainedHeaders(0, count, checkpoints, nil)
}

func (s HeaderState) validateRetainedHeaders(start, end int, checkpoints []Checkpoint, stop *atomic.Bool) error {
	for i := start; i < end; i++ {
		if stop != nil && stop.Load() {
			return nil
		}
		h := &s.RetainedWindow[i]
		bad := func(reason string) error {
			return fmt.Errorf("%w: header[%d]: %s", ErrInvalidRetainedState, i, reason)
		}
		if h.ChainIdentifier != s.Genesis.ChainID || h.Height <= s.Genesis.Height {
			return bad("chain identity or height")
		}
		if i == 0 {
			// Subtraction is safe after the height check and cannot wrap.
			if h.Height-s.Genesis.Height == 1 && h.PreviousHash != s.Genesis.HeaderHash {
				return bad("anchor linkage")
			}
		} else {
			previous := &s.RetainedWindow[i-1]
			if h.Height <= previous.Height || h.Height-previous.Height != 1 || h.PreviousHash != previous.HeaderHash {
				return bad("noncontiguous height or broken linkage")
			}
		}
		hash := h.ComputeHash()
		if hash != h.HeaderHash {
			return bad("hash mismatch")
		}
		if len(h.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(h.PublicKey, hash[:], h.Signature) {
			return bad("invalid signature")
		}
		if checkpoint, ok := CheckpointAtHeight(checkpoints, h.Height); ok && checkpoint.HeaderHash != h.HeaderHash {
			return bad("checkpoint mismatch")
		}
	}
	return nil
}

type limitedStateWriter struct {
	destination io.Writer
	remaining   int64
}

func (w *limitedStateWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, ErrStateFileTooLarge
	}
	n, err := w.destination.Write(p)
	w.remaining -= int64(n)
	return n, err
}
