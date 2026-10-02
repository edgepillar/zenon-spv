package main

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const binaryRecordLimit = 256

// Accept only the small, exact record emitted by compiled CLI helpers. A
// repeated or aliased key must not silently replace an executable identity.
func parseBinaryRecord(raw string) (binaryRecord, error) {
	invalid := errors.New("invalid executable record")
	var record binaryRecord
	if len(raw) > binaryRecordLimit {
		return record, invalid
	}
	d := json.NewDecoder(strings.NewReader(raw))
	if first, err := d.Token(); err != nil || first != json.Delim('{') {
		return record, invalid
	}
	fields := map[string]bool{"command": false, "sha256": false}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		seen, known := fields[key]
		var value string
		if err != nil || !ok || !known || seen || d.Decode(&value) != nil || value == "" {
			return binaryRecord{}, invalid
		}
		fields[key] = true
		if key == "command" {
			record.Command = value
		} else {
			record.SHA256 = value
		}
	}
	if last, err := d.Token(); err != nil || last != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return binaryRecord{}, invalid
	}
	if !fields["command"] || !fields["sha256"] || !hexDigest(record.SHA256, 64) {
		return binaryRecord{}, invalid
	}
	return record, nil
}
