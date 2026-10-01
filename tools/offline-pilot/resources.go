package main

import (
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
)

const resourceMarker = "offline-pilot-resource "

var resourceWorkloads = map[string][2]int{
	"M1_P1": {1, 1}, "M1000_P1": {1000, 1}, "M100000_P1": {100000, 1}, "M100000_P4": {100000, 4},
}

type resourceRecord struct {
	Workload        string  `json:"workload"`
	MembersPerProof int     `json:"members_per_proof"`
	Proofs          int     `json:"proofs"`
	InputBytes      int64   `json:"input_bytes"`
	ElapsedNS       int64   `json:"elapsed_ns"`
	PeakRSSBytes    *uint64 `json:"peak_rss_bytes"`
	PeakRSSSource   string  `json:"peak_rss_source"`
}

// Only fixed workload identifiers, bounded numbers and an accounting enum may
// reach a shareable report. Reject missing, repeated and unknown fields rather
// than copying arbitrary test output, paths or malformed measurements.
func parseResource(raw string) (resourceRecord, error) {
	return parseResourceOnPlatform(raw, runtime.GOOS)
}

func parseResourceOnPlatform(raw, platform string) (resourceRecord, error) {
	invalid := errors.New("invalid resource record")
	var record resourceRecord
	if len(raw) > 512 {
		return record, invalid
	}
	d := json.NewDecoder(strings.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return record, invalid
	}
	fields := map[string]bool{"workload": false, "members_per_proof": false, "proofs": false, "input_bytes": false,
		"elapsed_ns": false, "peak_rss_bytes": false, "peak_rss_source": false}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		seen, known := fields[key]
		if err != nil || !ok || !known || seen || d.Decode(new(json.RawMessage)) != nil {
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
	grid, known := resourceWorkloads[record.Workload]
	if !known || record.MembersPerProof != grid[0] || record.Proofs != grid[1] || record.InputBytes <= 0 || record.InputBytes > 64<<20 ||
		record.ElapsedNS <= 0 || record.ElapsedNS > 60_000_000_000 {
		return record, invalid
	}
	source := "unavailable"
	switch platform {
	case "linux", "darwin":
		source = "process_rusage"
	case "windows":
		source = "windows_peak_working_set"
	}
	if source != "unavailable" {
		if record.PeakRSSSource != source || record.PeakRSSBytes == nil || *record.PeakRSSBytes == 0 || *record.PeakRSSBytes > 1<<50 {
			return record, invalid
		}
	} else if record.PeakRSSSource != "unavailable" || record.PeakRSSBytes != nil {
		return record, invalid
	}
	return record, nil
}
