// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const (
	maxExperimentalConfigBytes  = 1 << 20
	maxExperimentalRequestBytes = 2048
	maxExperimentalBundleBytes  = 8 << 20
)

var (
	errExperimentalCLIInput              = errors.New("invalid experimental input")
	errExperimentalCLIGatewayUnavailable = errors.New("candidate gateway result is unavailable")
)

type experimentalCLIConfig struct {
	Version       uint32
	HeaderProfile verify.ExperimentalV3Profile
	HeaderPolicy  verify.ExperimentalV3Policy
	Schedule      *verify.ProducerSchedule
	QueryProfile  verify.ExperimentalBatchEntryProfile
}

// Exact required fields only. Null, aliases, duplicates and trailing values
// cannot silently replace a trust input or disable a selected comparison.
func decodeExperimentalCLIObject(raw []byte, fields map[string]any, nullable ...string) error {
	if !utf8.Valid(raw) {
		return errExperimentalCLIInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return errExperimentalCLIInput
	}
	seen := make(map[string]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		target, known := fields[name]
		if err != nil || !ok || !known || seen[name] {
			return errExperimentalCLIInput
		}
		seen[name] = true
		var value json.RawMessage
		allowNull := false
		for _, field := range nullable {
			allowNull = allowNull || field == name
		}
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !allowNull || json.Unmarshal(value, target) != nil {
			return errExperimentalCLIInput
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(seen) != len(fields) {
		return errExperimentalCLIInput
	}
	if d.Decode(new(any)) != io.EOF {
		return errExperimentalCLIInput
	}
	return nil
}

func decodeExperimentalCLIConfig(raw []byte) (experimentalCLIConfig, error) {
	var config experimentalCLIConfig
	var schedule json.RawMessage
	if len(raw) > maxExperimentalConfigBytes || decodeExperimentalCLIObject(raw, map[string]any{
		"version": &config.Version, "header_profile": &config.HeaderProfile,
		"header_policy": &config.HeaderPolicy, "producer_schedule": &schedule,
		"query_profile": &config.QueryProfile,
	}) != nil || config.Version != 1 {
		return experimentalCLIConfig{}, errExperimentalCLIInput
	}
	if boundExperimentalCLISchedule(schedule) != nil || json.Unmarshal(schedule, &config.Schedule) != nil {
		return experimentalCLIConfig{}, errExperimentalCLIInput
	}
	return config, nil
}

// The reusable native schedule decoder permits a much larger sidecar. Stop
// experimental row counts before asking that decoder to allocate its slices.
// Its existing strict schema/row/hash validation remains authoritative.
func boundExperimentalCLISchedule(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return errExperimentalCLIInput
	}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return errExperimentalCLIInput
		}
		if name != "coverage" && name != "entries" {
			if d.Decode(new(json.RawMessage)) != nil {
				return errExperimentalCLIInput
			}
			continue
		}
		if token, err := d.Token(); err != nil || token != json.Delim('[') {
			return errExperimentalCLIInput
		}
		count := 0
		for d.More() {
			if count == verify.MaxExperimentalV3ScheduleEntries || d.Decode(new(json.RawMessage)) != nil {
				return errExperimentalCLIInput
			}
			count++
		}
		if token, err := d.Token(); err != nil || token != json.Delim(']') {
			return errExperimentalCLIInput
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return errExperimentalCLIInput
	}
	return nil
}

type experimentalCLIBundle struct {
	Headers []chain.CandidateV3Header
	Witness proof.CandidateStateWitness
	Gateway *proof.CandidateSettlementBatch
}

func decodeExperimentalCLIHeaders(raw []byte, maxHeaders uint32) ([]chain.CandidateV3Header, error) {
	if len(raw) > maxExperimentalBundleBytes || maxHeaders == 0 || maxHeaders > verify.MaxRetainHeaders {
		return nil, errExperimentalCLIInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('[') {
		return nil, errExperimentalCLIInput
	}
	var headers []chain.CandidateV3Header
	for d.More() {
		if len(headers) >= int(maxHeaders) {
			return nil, errExperimentalCLIInput
		}
		var row json.RawMessage
		if d.Decode(&row) != nil {
			return nil, errExperimentalCLIInput
		}
		candidate, err := fetch.DecodeCandidateV3Momentum(row)
		if err != nil {
			return nil, errExperimentalCLIInput
		}
		headers = append(headers, candidate.Header)
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') || d.Decode(new(any)) != io.EOF {
		return nil, errExperimentalCLIInput
	}
	return headers, nil
}

// Request/configuration are separate local inputs, never members of a provider
// bundle. Gateway presence is selected by the command, not by this document.
func decodeExperimentalCLIBundle(raw []byte, maxHeaders uint32, compare bool) (experimentalCLIBundle, error) {
	if len(raw) > maxExperimentalBundleBytes || maxHeaders == 0 || maxHeaders > verify.MaxRetainHeaders {
		return experimentalCLIBundle{}, errExperimentalCLIInput
	}
	var version uint32
	var rows, witness, gateway json.RawMessage
	fields := map[string]any{"version": &version, "momentums": &rows, "witness": &witness}
	if compare {
		fields["gateway"] = &gateway
	}
	if decodeExperimentalCLIObject(raw, fields, "witness", "gateway") != nil || version != 1 {
		return experimentalCLIBundle{}, errExperimentalCLIInput
	}
	headers, err := decodeExperimentalCLIHeaders(rows, maxHeaders)
	if err != nil {
		return experimentalCLIBundle{}, errExperimentalCLIInput
	}
	next := experimentalCLIBundle{Headers: headers}
	if int64(len(witness)) > fetch.MaxCandidateStateResponseBytes || compare && int64(len(gateway)) > fetch.MaxCandidateStateResponseBytes {
		return experimentalCLIBundle{}, errExperimentalCLIInput
	}
	if next.Witness, err = fetch.DecodeCandidateStateWitness(witness); err != nil {
		return experimentalCLIBundle{}, err
	}
	if compare {
		value, err := fetch.DecodeCandidateSettlementBatch(gateway)
		if errors.Is(err, fetch.ErrCandidateStateUnavailable) {
			return experimentalCLIBundle{}, errExperimentalCLIGatewayUnavailable
		}
		if err != nil {
			return experimentalCLIBundle{}, err
		}
		next.Gateway = &value
	}
	return next, nil
}

// Regular-file checks precede open and are repeated on the descriptor. The
// file identity must match; byte caps include whitespace and concurrent growth.
// This is bounded local input, not authentication of file provenance.
func readExperimentalCLIFile(path string, limit int64, openFile func(string) (*os.File, error)) ([]byte, error) {
	if limit <= 0 || limit > maxExperimentalBundleBytes {
		return nil, errExperimentalCLIInput
	}
	selected, err := os.Lstat(path)
	if err != nil || !selected.Mode().IsRegular() || selected.Size() > limit {
		return nil, errExperimentalCLIInput
	}
	// Windows FileInfo resolves file IDs lazily through its saved path. Resolve
	// the selected ID now so a later path replacement cannot redefine it.
	if !os.SameFile(selected, selected) {
		return nil, errExperimentalCLIInput
	}
	f, err := openFile(path)
	if err != nil {
		return nil, errExperimentalCLIInput
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(selected, opened) || opened.Size() > limit {
		_ = f.Close()
		return nil, errExperimentalCLIInput
	}
	raw, readErr := readExperimentalCLIBytes(f, limit, opened.Size())
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) > limit {
		return nil, errExperimentalCLIInput
	}
	return raw, nil
}

// The opened regular file's size is an allocation hint, never an input bound.
// Stable files need one buffer; stale hints still read to EOF or one byte over
// the selected cap. Neither growth nor an unusable hint can relax that cap.
func readExperimentalCLIBytes(r io.Reader, maxBytes, sizeHint int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > maxExperimentalBundleBytes {
		return nil, errExperimentalCLIInput
	}
	// The fixed 8 MiB ceiling also bounds these conversions on 32-bit hosts.
	limit := int(maxBytes) + 1
	initial := min(512, limit)
	if sizeHint > 0 && sizeHint <= maxBytes {
		initial = max(initial, int(sizeHint)+1)
	}
	raw := make([]byte, 0, initial)
	for {
		n, err := r.Read(raw[len(raw):cap(raw)])
		raw = raw[:len(raw)+n]
		// A simultaneous data/error read must never become accepted input,
		// including when it supplies a complete document or the overflow byte.
		if err != nil && err != io.EOF {
			return nil, errExperimentalCLIInput
		}
		if len(raw) > int(maxBytes) {
			return nil, errExperimentalCLIInput
		}
		if err == io.EOF {
			return raw, nil
		}
		if len(raw) == cap(raw) {
			grown := make([]byte, len(raw), min(limit, cap(raw)*2))
			copy(grown, raw)
			raw = grown
		}
	}
}
