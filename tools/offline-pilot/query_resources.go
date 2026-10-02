package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
)

const queryResourceMarker = "offline-pilot-query-resource "
const queryResourceObservations = 21
const queryResourceRecordLimit = 16 << 10

var queryResourceWorkloads = map[string]int{"T1": 1, "T16": 16, "T256": 256}

type queryResourceObservation struct {
	ElapsedNS     int64   `json:"elapsed_ns"`
	PeakRSSBytes  *uint64 `json:"peak_rss_bytes"`
	PeakRSSSource string  `json:"peak_rss_source"`
}

type queryResourceRecord struct {
	Workload          string                     `json:"workload"`
	Targets           int                        `json:"targets"`
	ReportBytes       int64                      `json:"report_bytes"`
	ExpectationsBytes int64                      `json:"expectations_bytes"`
	ElapsedNS         int64                      `json:"elapsed_ns"`
	PeakRSSBytes      *uint64                    `json:"peak_rss_bytes"`
	PeakRSSSource     string                     `json:"peak_rss_source"`
	Observations      []queryResourceObservation `json:"observations"`
}

func parseQueryResource(raw string) (queryResourceRecord, error) {
	return parseQueryResourceOnPlatform(raw, runtime.GOOS)
}

// Keep report-consumer measurements separate from verifier evidence sizes.
// Only a fixed batch identifier, bounded integers and the native accounting
// source may enter a shareable report; never copy arbitrary test diagnostics.
func parseQueryResourceOnPlatform(raw, platform string) (queryResourceRecord, error) {
	invalid := errors.New("invalid query resource record")
	var record queryResourceRecord
	if len(raw) > queryResourceRecordLimit {
		return record, invalid
	}
	d := json.NewDecoder(strings.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return record, invalid
	}
	fields := map[string]bool{"workload": false, "targets": false, "report_bytes": false, "expectations_bytes": false,
		"elapsed_ns": false, "peak_rss_bytes": false, "peak_rss_source": false, "observations": false}
	var observations json.RawMessage
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		seen, known := fields[key]
		var value json.RawMessage
		if err != nil || !ok || !known || seen || d.Decode(&value) != nil || (key != "peak_rss_bytes" && bytes.Equal(value, []byte("null"))) {
			return record, invalid
		}
		fields[key] = true
		if key == "observations" {
			observations = value
		}
	}
	if last, err := d.Token(); err != nil || last != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return record, invalid
	}
	for _, seen := range fields {
		if !seen {
			return record, invalid
		}
	}
	if json.Unmarshal([]byte(raw), &record) != nil {
		return record, invalid
	}
	targets, known := queryResourceWorkloads[record.Workload]
	if !known || record.Targets != targets || record.ReportBytes <= 0 || record.ReportBytes > 4<<20 ||
		record.ExpectationsBytes <= 0 || record.ExpectationsBytes > 256<<10 || record.ElapsedNS <= 0 || record.ElapsedNS > 60_000_000_000 ||
		!validResourceMemory(record.PeakRSSBytes, record.PeakRSSSource, platform) {
		return record, invalid
	}
	// Validate nested object keys independently of struct decoding, which would
	// otherwise accept unknown fields, case aliases and duplicate measurements.
	var points []json.RawMessage
	if json.Unmarshal(observations, &points) != nil || len(points) != queryResourceObservations {
		return record, invalid
	}
	for _, point := range points {
		if !validQueryResourceObservation(point, platform) {
			return record, invalid
		}
	}
	firstObservation := record.Observations[0]
	if firstObservation.ElapsedNS != record.ElapsedNS || firstObservation.PeakRSSSource != record.PeakRSSSource ||
		!sameQueryResourcePeak(firstObservation.PeakRSSBytes, record.PeakRSSBytes) {
		return record, invalid
	}
	return record, nil
}

func validQueryResourceObservation(raw json.RawMessage, platform string) bool {
	if len(raw) > 256 {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if first, err := d.Token(); err != nil || first != json.Delim('{') {
		return false
	}
	fields := map[string]bool{"elapsed_ns": false, "peak_rss_bytes": false, "peak_rss_source": false}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		seen, known := fields[key]
		var value json.RawMessage
		if err != nil || !ok || !known || seen || d.Decode(&value) != nil || (key != "peak_rss_bytes" && bytes.Equal(value, []byte("null"))) {
			return false
		}
		fields[key] = true
	}
	if last, err := d.Token(); err != nil || last != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return false
	}
	for _, seen := range fields {
		if !seen {
			return false
		}
	}
	var point queryResourceObservation
	return json.Unmarshal(raw, &point) == nil && point.ElapsedNS > 0 && point.ElapsedNS <= 60_000_000_000 &&
		validResourceMemory(point.PeakRSSBytes, point.PeakRSSSource, platform)
}

func sameQueryResourcePeak(a, b *uint64) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
