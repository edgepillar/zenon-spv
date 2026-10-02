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

var queryResourceWorkloads = map[string]int{"T1": 1, "T16": 16, "T256": 256}

type queryResourceRecord struct {
	Workload          string  `json:"workload"`
	Targets           int     `json:"targets"`
	ReportBytes       int64   `json:"report_bytes"`
	ExpectationsBytes int64   `json:"expectations_bytes"`
	ElapsedNS         int64   `json:"elapsed_ns"`
	PeakRSSBytes      *uint64 `json:"peak_rss_bytes"`
	PeakRSSSource     string  `json:"peak_rss_source"`
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
	if len(raw) > 512 {
		return record, invalid
	}
	d := json.NewDecoder(strings.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return record, invalid
	}
	fields := map[string]bool{"workload": false, "targets": false, "report_bytes": false, "expectations_bytes": false,
		"elapsed_ns": false, "peak_rss_bytes": false, "peak_rss_source": false}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		seen, known := fields[key]
		var value json.RawMessage
		if err != nil || !ok || !known || seen || d.Decode(&value) != nil || (key != "peak_rss_bytes" && bytes.Equal(value, []byte("null"))) {
			return record, invalid
		}
		fields[key] = true
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
	return record, nil
}
