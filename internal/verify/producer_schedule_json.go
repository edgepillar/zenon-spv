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
	return s.unmarshalJSON(raw, MaxProducerScheduleEntries)
}

// DecodeExperimentalV3Schedule decodes the shared schedule schema with the
// experimental row limit. The caller still validates and pins the schedule.
func DecodeExperimentalV3Schedule(raw []byte) (*ProducerSchedule, error) {
	var schedule ProducerSchedule
	if err := schedule.unmarshalJSON(raw, MaxExperimentalV3ScheduleEntries); err != nil {
		return nil, err
	}
	return &schedule, nil
}

func (s *ProducerSchedule) unmarshalJSON(raw []byte, maxRows int) error {
	if len(raw) > MaxProducerScheduleFileBytes {
		return ErrProducerScheduleTooLarge
	}
	var next ProducerSchedule
	fields := []struct {
		name     string
		target   any
		required bool
	}{
		{"chain_id", &next.ChainID, true},
		{"coverage", func(d *json.Decoder) error {
			return decodeScheduleRows(d, &next.Coverage, "coverage", maxRows)
		}, true},
		{"entries", func(d *json.Decoder) error {
			return decodeScheduleRows(d, &next.Entries, "entries", maxRows)
		}, true},
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
		if readRows, ok := field.target.(func(*json.Decoder) error); ok {
			if err := readRows(d); err != nil {
				return err
			}
			continue
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return fmt.Errorf("%w: malformed field value", errInvalidScheduleJSON)
		}
		if field.required && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%w: %s must be non-null", errInvalidScheduleJSON, field.name)
		}
		if err := json.Unmarshal(value, field.target); err != nil {
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
	*s = next
	return nil
}

// Decode array rows directly from the schedule decoder so the selected count
// limit applies before decoding the next row or growing the result.
func decodeScheduleRows[T any](d *json.Decoder, target *[]T, name string, maxRows int) error {
	first, err := d.Token()
	if err != nil {
		return fmt.Errorf("%w: malformed field value", errInvalidScheduleJSON)
	}
	if first == nil {
		return fmt.Errorf("%w: %s must be non-null", errInvalidScheduleJSON, name)
	}
	if first != json.Delim('[') {
		return fmt.Errorf("%w: invalid %s", errInvalidScheduleJSON, name)
	}
	rows := make([]T, 0)
	for d.More() {
		if len(rows) == maxRows {
			return ErrProducerScheduleTooLarge
		}
		var row T
		if err := d.Decode(&row); err != nil {
			return fmt.Errorf("%w: invalid %s", errInvalidScheduleJSON, name)
		}
		rows = append(rows, row)
	}
	if end, err := d.Token(); err != nil || end != json.Delim(']') {
		return fmt.Errorf("%w: invalid %s", errInvalidScheduleJSON, name)
	}
	*target = rows
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
