package verify

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
)

// Keep the explicit top-level encoding below synchronized with the persisted
// schema. Adding or reordering a field requires reviewing this positional guard.
var _ = persistedState{nil, 0, GenesisTrustRoot{}, nil, 0}

type stateEncodingWriter struct {
	limitedStateWriter
}

func (w *stateEncodingWriter) Write(raw []byte) (int, error) {
	n, err := w.limitedStateWriter.Write(raw)
	if err == nil && n < len(raw) {
		err = io.ErrShortWrite
	}
	return n, err
}

// encodePersistedState preserves the existing indented JSON bytes while keeping
// the encoding/json value buffer to one metadata value or retained header. The
// output buffer amortizes file writes; the existing byte cap applies before any
// bytes reach the destination. Callers keep the atomic temporary-file protocol.
func encodePersistedState(destination io.Writer, body persistedState) error {
	bufferBytes := 32 << 10
	if len(body.Window) < 31 {
		bufferBytes = (1 + len(body.Window)) << 10
	}
	out := bufio.NewWriterSize(&stateEncodingWriter{limitedStateWriter{destination: destination, remaining: MaxStateFileBytes}}, bufferBytes)
	var value bytes.Buffer
	encoder := json.NewEncoder(&value)
	write := func(raw string) error {
		_, err := out.WriteString(raw)
		return err
	}
	emit := func(prefix string, item any) error {
		value.Reset()
		encoder.SetIndent(prefix, "  ")
		if err := encoder.Encode(item); err != nil {
			return err
		}
		// Encoder.Encode appends exactly one newline. The surrounding object
		// or array supplies the comma and newline after this complete value.
		raw := value.Bytes()
		_, err := out.Write(raw[:len(raw)-1])
		return err
	}
	field := func(name string, item any, ending string) error {
		if err := write("  \"" + name + "\": "); err != nil {
			return err
		}
		if err := emit("  ", item); err != nil {
			return err
		}
		return write(ending)
	}
	if err := write("{\n"); err != nil {
		return err
	}
	if body.ProtocolProfile != nil {
		if err := field("protocol_profile", body.ProtocolProfile, ",\n"); err != nil {
			return err
		}
	}
	if err := field("version", body.Version, ",\n"); err != nil {
		return err
	}
	if err := field("genesis", body.Genesis, ",\n"); err != nil {
		return err
	}
	switch {
	case body.Window == nil:
		if err := write("  \"retained_window\": null,\n"); err != nil {
			return err
		}
	case len(body.Window) == 0:
		if err := write("  \"retained_window\": [],\n"); err != nil {
			return err
		}
	default:
		if err := write("  \"retained_window\": [\n"); err != nil {
			return err
		}
		for i, header := range body.Window {
			if err := write("    "); err != nil {
				return err
			}
			if err := emit("    ", header); err != nil {
				return err
			}
			ending := ",\n"
			if i == len(body.Window)-1 {
				ending = "\n"
			}
			if err := write(ending); err != nil {
				return err
			}
		}
		if err := write("  ],\n"); err != nil {
			return err
		}
	}
	if err := field("capacity", body.Capacity, "\n"); err != nil {
		return err
	}
	if err := write("}\n"); err != nil {
		return err
	}
	return out.Flush()
}
