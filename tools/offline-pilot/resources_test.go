package main

import (
	"encoding/json"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func sampleResource(t *testing.T, name string) string {
	t.Helper()
	grid := resourceWorkloads[name]
	record := resourceRecord{Workload: name, MembersPerProof: grid[0], Proofs: grid[1], InputBytes: 1000,
		ElapsedNS: 1000000, PeakRSSSource: "unavailable"}
	switch runtime.GOOS {
	case "linux", "darwin":
		peak := uint64(1 << 20)
		record.PeakRSSBytes, record.PeakRSSSource = &peak, "process_rusage"
	case "windows":
		peak := uint64(1 << 20)
		record.PeakRSSBytes, record.PeakRSSSource = &peak, "windows_peak_working_set"
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestResourceMemorySourceIsBoundToPlatform(t *testing.T) {
	for _, platform := range []string{"linux", "darwin", "windows", "freebsd"} {
		for _, source := range []string{"process_rusage", "windows_peak_working_set", "unavailable", "sampled_maximum", "PRIVATE_ENDPOINT"} {
			for _, peak := range []string{"null", "0", "1048576", "1125899906842625"} {
				var record map[string]json.RawMessage
				if json.Unmarshal([]byte(sampleResource(t, "M1_P1")), &record) != nil {
					t.Fatal("sample record malformed")
				}
				record["peak_rss_bytes"] = json.RawMessage(peak)
				record["peak_rss_source"], _ = json.Marshal(source)
				raw, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				_, err = parseResourceOnPlatform(string(raw), platform)
				want := (platform == "linux" || platform == "darwin") && source == "process_rusage" && peak == "1048576" ||
					platform == "windows" && source == "windows_peak_working_set" && peak == "1048576" ||
					platform == "freebsd" && source == "unavailable" && peak == "null"
				if (err == nil) != want || (err != nil && strings.Contains(err.Error(), "PRIVATE")) {
					t.Fatal("platform accepted a missing, substituted, impossible or private memory source")
				}
			}
		}
	}
}

func TestResourceRecordPrivacyAndCompleteness(t *testing.T) {
	raw := sampleResource(t, "M1_P1")
	if _, err := parseResource(raw); err != nil {
		t.Fatal("valid native measurement refused")
	}
	for _, input := range []string{
		strings.Replace(raw, "M1_P1", "PRIVATE_PATH", 1),
		strings.Replace(raw, `"members_per_proof":1`, `"members_per_proof":2`, 1),
		strings.Replace(raw, `"elapsed_ns":1000000`, `"elapsed_ns":0`, 1),
		strings.Replace(raw, `"elapsed_ns":1000000`, `"elapsed_ns":60000000001`, 1),
		strings.Replace(raw, `"input_bytes":1000`, `"input_bytes":67108865`, 1),
		strings.Replace(raw, `"input_bytes":1000,`, "", 1),
		strings.Replace(raw, `"input_bytes":1000`, `"input_bytes":1000,"input_bytes":1000`, 1),
		strings.Replace(raw, `"input_bytes":1000`, `"input_bytes":1000,"path":"PRIVATE_PATH"`, 1),
		strings.Replace(raw, `"peak_rss_source":`, `"peak_rss_source":"PRIVATE_ENDPOINT","unknown":`, 1),
		strings.Replace(raw, `"peak_rss_bytes":`, `"peak_rss_bytes":0,"unknown":`, 1),
		raw + " {}", "{PRIVATE}", strings.Repeat("PRIVATE", 100),
	} {
		if _, err := parseResource(input); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid measurement accepted or private input echoed")
		}
	}
}

func TestResourceReportRequiresEveryExecutedWorkload(t *testing.T) {
	manifest := []scenario{{"compiled_content_scaling", "internal/conformance", "TestExample", []string{"zenon-spv"}}}
	base := sampleEvents()
	events := slices.Clone(base[:3])
	for _, name := range []string{"M1_P1", "M1000_P1", "M100000_P1", "M100000_P4"} {
		child := "TestExample/" + name
		events = append(events,
			testEvent{Action: "run", Package: base[0].Package, Test: child},
			testEvent{Action: "output", Package: base[0].Package, Test: child, Output: resourceMarker + sampleResource(t, name)},
			testEvent{Action: "pass", Package: base[0].Package, Test: child})
	}
	events = append(events, base[5:]...)
	for _, mode := range []string{"complete", "missing", "duplicate", "outside execution", "wrong child", "wrong case"} {
		t.Run(mode, func(t *testing.T) {
			c := newCollector(manifest)
			input := slices.Clone(events)
			switch mode {
			case "missing":
				input[4].Output = "regular output"
			case "duplicate":
				input = slices.Insert(input, 5, input[4])
			case "outside execution":
				input[3], input[4] = input[4], input[3]
			case "wrong child":
				input[4].Output = resourceMarker + sampleResource(t, "M1000_P1")
			case "wrong case":
				c.cases[0].ID = "sample"
			}
			var eventErr error
			for _, event := range input {
				if eventErr = c.event(event); eventErr != nil {
					break
				}
			}
			switch mode {
			case "complete":
				if eventErr != nil || c.finish(true) != "passed" || len(c.cases[0].Resources) != 4 {
					t.Fatal("complete measurements lost")
				}
			case "missing":
				if eventErr != nil || c.finish(true) != "incomplete" {
					t.Fatal("missing measurement reported complete")
				}
			default:
				if eventErr == nil {
					t.Fatal("ambiguous measurement execution accepted")
				}
			}
		})
	}
}
