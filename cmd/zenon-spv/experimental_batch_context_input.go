// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type experimentalContextCLIConfig struct {
	Version       uint32
	HeaderProfile verify.ExperimentalV3Profile
	HeaderPolicy  verify.ExperimentalV3Policy
	Schedule      *verify.ProducerSchedule
	QueryProfile  verify.ExperimentalBatchContextProfile
}

func decodeExperimentalContextCLIConfig(raw []byte) (experimentalContextCLIConfig, error) {
	var next experimentalContextCLIConfig
	var schedule json.RawMessage
	if len(raw) > maxExperimentalConfigBytes || decodeExperimentalCLIObject(raw, map[string]any{
		"version": &next.Version, "header_profile": &next.HeaderProfile, "header_policy": &next.HeaderPolicy,
		"producer_schedule": &schedule, "query_profile": &next.QueryProfile,
	}) != nil || next.Version != 1 || boundExperimentalCLISchedule(schedule) != nil || json.Unmarshal(schedule, &next.Schedule) != nil {
		return experimentalContextCLIConfig{}, errExperimentalCLIInput
	}
	return next, nil
}

type experimentalContextCLIBundle struct {
	Headers   []chain.CandidateV3Header
	Witnesses verify.ExperimentalBatchContextWitnesses
	Gateway   *proof.CandidateSettlementBatch
}

func decodeExperimentalContextCLIBundle(raw []byte, maxHeaders uint32, compare bool) (experimentalContextCLIBundle, error) {
	if len(raw) > maxExperimentalBundleBytes || maxHeaders == 0 || maxHeaders > verify.MaxRetainHeaders {
		return experimentalContextCLIBundle{}, errExperimentalCLIInput
	}
	var version uint32
	var rows, witnesses, gateway json.RawMessage
	fields := map[string]any{"version": &version, "momentums": &rows, "witnesses": &witnesses}
	if compare {
		fields["gateway"] = &gateway
	}
	if decodeExperimentalCLIObject(raw, fields, "witnesses", "gateway") != nil || version != 1 {
		return experimentalContextCLIBundle{}, errExperimentalCLIInput
	}
	var entry, record, config json.RawMessage
	if decodeExperimentalCLIObject(witnesses, map[string]any{
		"batch_entry": &entry, "domain_record": &record, "domain_config": &config,
	}, "batch_entry", "domain_record", "domain_config") != nil {
		return experimentalContextCLIBundle{}, errExperimentalCLIInput
	}
	var next experimentalContextCLIBundle
	for _, hint := range [...]struct {
		raw    json.RawMessage
		target *proof.CandidateStateWitness
	}{{entry, &next.Witnesses.BatchEntry}, {record, &next.Witnesses.DomainRecord}, {config, &next.Witnesses.DomainConfig}} {
		if int64(len(hint.raw)) > fetch.MaxCandidateStateResponseBytes {
			return experimentalContextCLIBundle{}, errExperimentalCLIInput
		}
		value, err := fetch.DecodeCandidateStateWitness(hint.raw)
		if err != nil {
			return experimentalContextCLIBundle{}, err
		}
		*hint.target = value
	}
	d := json.NewDecoder(bytes.NewReader(rows))
	if token, err := d.Token(); err != nil || token != json.Delim('[') {
		return experimentalContextCLIBundle{}, errExperimentalCLIInput
	}
	for d.More() {
		if len(next.Headers) >= int(maxHeaders) {
			return experimentalContextCLIBundle{}, errExperimentalCLIInput
		}
		var row json.RawMessage
		if d.Decode(&row) != nil {
			return experimentalContextCLIBundle{}, errExperimentalCLIInput
		}
		h, err := fetch.DecodeCandidateV3Momentum(row)
		if err != nil {
			return experimentalContextCLIBundle{}, errExperimentalCLIInput
		}
		next.Headers = append(next.Headers, h.Header)
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') || d.Decode(new(any)) != io.EOF {
		return experimentalContextCLIBundle{}, errExperimentalCLIInput
	}
	if compare {
		if int64(len(gateway)) > fetch.MaxCandidateStateResponseBytes {
			return experimentalContextCLIBundle{}, errExperimentalCLIInput
		}
		if bytes.Equal(bytes.TrimSpace(gateway), []byte("null")) {
			return experimentalContextCLIBundle{}, errExperimentalCLIGatewayUnavailable
		}
		decoded, err := fetch.DecodeCandidateSettlementBatch(gateway)
		if err != nil {
			return experimentalContextCLIBundle{}, err
		}
		next.Gateway = &decoded
	}
	return next, nil
}
