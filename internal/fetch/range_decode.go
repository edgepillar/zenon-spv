package fetch

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// rpcListDecoder binds allocation of a range result to the requested count.
// The caller applies the response byte and envelope limits before decoding.
// Decode into a temporary list so failures never expose partial rows.
type rpcListDecoder[T any] struct {
	target *[]T
	count  uint64
	// rowTarget optionally wraps each row with call/range-scoped decoding limits.
	rowTarget func(*T) any
}

func (list *rpcListDecoder[T]) UnmarshalJSON(raw []byte) error {
	wire := struct {
		List rpcListRows[T] `json:"list"`
	}{List: rpcListRows[T]{count: list.count, rowTarget: list.rowTarget}}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	*list.target = wire.List.rows
	return nil
}

type rpcListRows[T any] struct {
	rows      []T
	count     uint64
	seen      bool
	rowTarget func(*T) any
}

func (list *rpcListRows[T]) UnmarshalJSON(raw []byte) error {
	// encoding/json invokes this for escaped and case-folded aliases too.
	// Replacing or clearing a prior list cannot bypass the request count.
	if list.seen {
		return fmt.Errorf("%w: duplicate range list", ErrInvalidRPCResponse)
	}
	list.seen = true
	if bytes.Equal(raw, []byte("null")) {
		list.rows = nil
		return nil
	}
	if len(raw) < 2 || raw[0] != '[' || raw[len(raw)-1] != ']' {
		return fmt.Errorf("%w: range list must be an array or null", ErrInvalidRPCResponse)
	}

	// json.Unmarshal in rpcListDecoder validated the entire array before
	// invoking this method. Locate each row in those bytes and decode it
	// without copying it into a streaming decoder's scratch buffer.
	decoded := make([]T, 0)
	const whitespace = " \t\r\n"
	remaining := bytes.TrimLeft(raw[1:len(raw)-1], whitespace)
	for len(remaining) != 0 {
		if uint64(len(decoded)) >= list.count {
			return fmt.Errorf("%w: range list exceeds requested count %d", ErrQueryMismatch, list.count)
		}
		end := rpcJSONValueEnd(remaining)
		var row T
		var target any = &row
		if list.rowTarget != nil {
			target = list.rowTarget(&row)
		}
		value := remaining[:end:end]
		var err error
		if decoder, ok := target.(json.Unmarshaler); ok {
			// The row is already valid JSON. Let the configured decoder apply
			// its schema directly, without another generic decoder pass.
			err = decoder.UnmarshalJSON(value)
		} else {
			err = json.Unmarshal(value, target)
		}
		if err != nil {
			return err
		}
		decoded = append(decoded, row)
		remaining = bytes.TrimLeft(remaining[end:], whitespace)
		if len(remaining) != 0 {
			remaining = bytes.TrimLeft(remaining[1:], whitespace) // Consume the comma.
		}
	}
	list.rows = decoded
	return nil
}
