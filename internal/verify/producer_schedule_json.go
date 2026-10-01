package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var errInvalidScheduleJSON = errors.New("invalid producer schedule JSON")

// UnmarshalJSON rejects ambiguous authority before Validate builds an index.
// Substantive fields are required; audit metadata remains optional and does
// not authenticate the schedule. A failed decode leaves the receiver intact.
func (s *ProducerSchedule) UnmarshalJSON(raw []byte) error {
	if len(raw) > MaxProducerScheduleFileBytes {
		return ErrProducerScheduleTooLarge
	}
	var next ProducerSchedule
	var coverage boundedScheduleRows[ProducerCoverage]
	var entries boundedScheduleRows[ProducerEntry]
	fields := []struct {
		name     string
		target   any
		required bool
	}{
		{"chain_id", &next.ChainID, true},
		{"coverage", &coverage, true},
		{"entries", &entries, true},
		{"schedule_hash", &next.ScheduleHash, true},
		{"generated_at", &next.GeneratedAt, false},
		{"source_peers", &next.SourcePeers, false},
		{"source_heights", &next.SourceHeights, false},
	}
	seen := make([]bool, len(fields))
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return fmt.Errorf("%w: expected an object", errInvalidScheduleJSON)
	}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return fmt.Errorf("%w: invalid field name", errInvalidScheduleJSON)
		}
		index := -1
		for i, field := range fields {
			if name == field.name {
				index = i
				break
			}
		}
		if index == -1 {
			return fmt.Errorf("%w: unknown field", errInvalidScheduleJSON)
		}
		if seen[index] {
			return fmt.Errorf("%w: duplicate field", errInvalidScheduleJSON)
		}
		seen[index] = true
		field := fields[index]
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return fmt.Errorf("%w: malformed field value", errInvalidScheduleJSON)
		}
		if field.required && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%w: %s must be non-null", errInvalidScheduleJSON, field.name)
		}
		if err := json.Unmarshal(value, field.target); err != nil {
			if errors.Is(err, ErrProducerScheduleTooLarge) {
				return err
			}
			// Only fixed schema names are safe in ordinary diagnostics.
			return fmt.Errorf("%w: invalid %s", errInvalidScheduleJSON, field.name)
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("%w: malformed object ending", errInvalidScheduleJSON)
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON", errInvalidScheduleJSON)
	}
	for i, field := range fields {
		if field.required && !seen[i] {
			return fmt.Errorf("%w: missing %s", errInvalidScheduleJSON, field.name)
		}
	}
	next.Coverage, next.Entries = coverage, entries
	*s = next
	return nil
}

func (c *ProducerCoverage) UnmarshalJSON(raw []byte) error {
	var next ProducerCoverage
	if err := decodeRequiredObject(raw, map[string]any{
		"from_height": &next.FromHeight, "through_height": &next.ThroughHeight,
	}); err != nil {
		return fmt.Errorf("%w: invalid coverage row", errInvalidScheduleJSON)
	}
	*c = next
	return nil
}

func (e *ProducerEntry) UnmarshalJSON(raw []byte) error {
	var next ProducerEntry
	if err := decodeRequiredObject(raw, map[string]any{
		"height": &next.Height, "timestamp_unix": &next.TimestampUnix, "producing_addr": &next.ProducingAddr,
	}); err != nil {
		return fmt.Errorf("%w: invalid producer row", errInvalidScheduleJSON)
	}
	*e = next
	return nil
}
