package fetch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// rpcListDecoder binds allocation of a range result to the requested count.
// The enclosing Call still applies the response byte and JSON syntax limits.
// Decode into a temporary list so failures never expose partial rows.
type rpcListDecoder[T any] struct {
	target *[]T
	count  uint64
}

func (list *rpcListDecoder[T]) UnmarshalJSON(raw []byte) error {
	wire := struct {
		List rpcListRows[T] `json:"list"`
	}{List: rpcListRows[T]{count: list.count}}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	*list.target = wire.List.rows
	return nil
}

type rpcListRows[T any] struct {
	rows  []T
	count uint64
	seen  bool
}

func (list *rpcListRows[T]) UnmarshalJSON(raw []byte) error {
	// encoding/json invokes this for escaped and case-folded aliases too.
	// Replacing or clearing a prior list cannot bypass the request count.
	if list.seen {
		return fmt.Errorf("%w: duplicate range list", ErrInvalidRPCResponse)
	}
	list.seen = true
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil {
		return err
	}
	var decoded []T
	if first != nil {
		if first != json.Delim('[') {
			return fmt.Errorf("%w: range list must be an array or null", ErrInvalidRPCResponse)
		}
		decoded = make([]T, 0)
		for d.More() {
			if uint64(len(decoded)) >= list.count {
				return fmt.Errorf("%w: range list exceeds requested count %d", ErrQueryMismatch, list.count)
			}
			var row T
			if err := d.Decode(&row); err != nil {
				return err
			}
			decoded = append(decoded, row)
		}
		if _, err := d.Token(); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing range list data", ErrInvalidRPCResponse)
	}
	list.rows = decoded
	return nil
}
