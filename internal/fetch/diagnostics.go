package fetch

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// PeerLabel identifies a zero-based configuration position without copying
// endpoint credentials, hostnames, paths, or query parameters into diagnostics.
// It is a display label, not a stable peer identity or independence claim.
func PeerLabel(index int) string { return fmt.Sprintf("peer[%d]", index+1) }

// rpcCallFailure has safe ordinary formatting but preserves the original cause
// for errors.Is/errors.As. Callers explicitly inspecting that cause must treat
// it as private: it can contain an endpoint, credentials, or remote payload.
type rpcCallFailure struct {
	message string
	cause   error
}

func (e *rpcCallFailure) Error() string { return e.message }
func (e *rpcCallFailure) Unwrap() error { return e.cause }

func callFailure(stage string, cause error) error {
	message := "rpc " + stage + " failed"
	var networkError net.Error
	switch {
	case errors.Is(cause, context.Canceled):
		message += ": context canceled"
	case errors.Is(cause, context.DeadlineExceeded):
		message += ": deadline exceeded"
	case errors.As(cause, &networkError) && networkError.Timeout():
		message += ": timeout"
	}
	return &rpcCallFailure{message: message, cause: cause}
}
