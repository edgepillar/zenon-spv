package verify

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"

	"github.com/0x3639/zenon-spv/internal/chain"
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
// the encoding/json value buffer to one metadata value. Each retained header
// uses a reusable row buffer. The output buffer amortizes file writes and the
// byte cap applies before output reaches the destination. Callers keep the
// atomic temporary-file protocol.
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
		row := make([]byte, 0, 1024)
		for i := range body.Window {
			row = appendPersistedHeader(row[:0], &body.Window[i])
			if _, err := out.Write(row); err != nil {
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

// appendPersistedHeader mirrors the field order, indentation and encodings of
// chain.Header in the persisted JSON. The byte-parity tests use encoding/json
// as the reference, including the nil and empty forms of key and signature.
func appendPersistedHeader(dst []byte, header *chain.Header) []byte {
	dst = append(dst, "    {\n      \"version\": "...)
	dst = strconv.AppendUint(dst, header.Version, 10)
	field := func(name string) {
		dst = append(dst, ",\n      \""...)
		dst = append(dst, name...)
		dst = append(dst, "\": "...)
	}
	number := func(name string, value uint64) {
		field(name)
		dst = strconv.AppendUint(dst, value, 10)
	}
	hash := func(name string, value *chain.Hash) {
		field(name)
		dst = append(dst, '"')
		dst = hex.AppendEncode(dst, value[:])
		dst = append(dst, '"')
	}
	binary := func(name string, value []byte) {
		field(name)
		if value == nil {
			dst = append(dst, "null"...)
			return
		}
		dst = append(dst, '"')
		dst = base64.StdEncoding.AppendEncode(dst, value)
		dst = append(dst, '"')
	}

	number("chainIdentifier", header.ChainIdentifier)
	hash("hash", &header.HeaderHash)
	hash("previousHash", &header.PreviousHash)
	number("height", header.Height)
	number("timestamp", header.TimestampUnix)
	hash("dataHash", &header.DataHash)
	hash("contentHash", &header.ContentHash)
	hash("changesHash", &header.ChangesHash)
	binary("publicKey", header.PublicKey)
	binary("signature", header.Signature)
	number("nextFusionPrice", header.NextFusionPrice)
	number("nextWorkPrice", header.NextWorkPrice)
	return append(dst, "\n    }"...)
}
