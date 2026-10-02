package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func sampleQueryResource(t *testing.T, name string) string {
	t.Helper()
	var memory resourceRecord
	if json.Unmarshal([]byte(sampleResource(t, "M1_P1")), &memory) != nil {
		t.Fatal("sample memory malformed")
	}
	record := queryResourceRecord{Workload: name, Targets: queryResourceWorkloads[name], ReportBytes: 1000, ExpectationsBytes: 500,
		ElapsedNS: 1000000, PeakRSSBytes: memory.PeakRSSBytes, PeakRSSSource: memory.PeakRSSSource}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestQueryResourcePrivacyAndBounds(t *testing.T) {
	raw := sampleQueryResource(t, "T1")
	if _, err := parseQueryResource(raw); err != nil {
		t.Fatal("valid native query measurement refused")
	}
	for _, input := range []string{
		strings.Replace(raw, "T1", "PRIVATE_PATH", 1),
		strings.Replace(raw, `"targets":1`, `"targets":16`, 1),
		strings.Replace(raw, `"report_bytes":1000`, `"report_bytes":0`, 1),
		strings.Replace(raw, `"report_bytes":1000`, `"report_bytes":4194305`, 1),
		strings.Replace(raw, `"expectations_bytes":500`, `"expectations_bytes":0`, 1),
		strings.Replace(raw, `"expectations_bytes":500`, `"expectations_bytes":262145`, 1),
		strings.Replace(raw, `"elapsed_ns":1000000`, `"elapsed_ns":0`, 1),
		strings.Replace(raw, `"elapsed_ns":1000000`, `"elapsed_ns":60000000001`, 1),
		strings.Replace(raw, `"report_bytes":1000,`, "", 1),
		strings.Replace(raw, `"report_bytes":1000`, `"report_bytes":1000,"report_bytes":1000`, 1),
		strings.Replace(raw, `"report_bytes":1000`, `"report_bytes":1000,"report_\u0062ytes":1000`, 1),
		strings.Replace(raw, `"report_bytes":`, `"Report_Bytes":`, 1),
		strings.Replace(raw, `"report_bytes":1000`, `"report_bytes":1000,"path":"PRIVATE_PATH"`, 1),
		raw + " {}", "{PRIVATE}", strings.Repeat("PRIVATE", 100),
	} {
		if _, err := parseQueryResource(input); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid query measurement accepted or private input echoed")
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil {
		t.Fatal("sample record malformed")
	}
	for key, original := range fields {
		if key != "peak_rss_bytes" {
			fields[key] = json.RawMessage("null")
			input, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseQueryResource(string(input)); err == nil {
				t.Fatal("null required measurement accepted")
			}
			fields[key] = original
		}
	}
	for _, value := range []string{"1000.0", "1e3", "-1", "18446744073709551616", `"PRIVATE_VALUE"`, "[]", "{}"} {
		fields["report_bytes"] = json.RawMessage(value)
		input, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseQueryResource(string(input)); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid numeric measurement accepted or echoed")
		}
	}
	for _, name := range []string{"T1", "T16", "T256"} {
		input := strings.Replace(sampleQueryResource(t, name), `"report_bytes":1000`, `"report_bytes":4194304`, 1)
		input = strings.Replace(input, `"expectations_bytes":500`, `"expectations_bytes":262144`, 1)
		if _, err := parseQueryResource(input); err != nil {
			t.Fatal("inclusive byte caps or a supported batch refused")
		}
	}
}

func TestQueryResourceMemorySourceIsBoundToPlatform(t *testing.T) {
	for _, platform := range []string{"linux", "darwin", "windows", "freebsd"} {
		for _, source := range []string{"process_rusage", "windows_peak_working_set", "unavailable", "sampled_maximum", "PRIVATE_ENDPOINT"} {
			for _, peak := range []string{"null", "0", "1048576", "1125899906842625"} {
				var fields map[string]json.RawMessage
				if json.Unmarshal([]byte(sampleQueryResource(t, "T1")), &fields) != nil {
					t.Fatal("sample record malformed")
				}
				fields["peak_rss_bytes"] = json.RawMessage(peak)
				fields["peak_rss_source"], _ = json.Marshal(source)
				raw, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				_, err = parseQueryResourceOnPlatform(string(raw), platform)
				want := (platform == "linux" || platform == "darwin") && source == "process_rusage" && peak == "1048576" ||
					platform == "windows" && source == "windows_peak_working_set" && peak == "1048576" ||
					platform == "freebsd" && source == "unavailable" && peak == "null"
				if (err == nil) != want || (err != nil && strings.Contains(err.Error(), "PRIVATE")) {
					t.Fatal("query measurement accepted a substituted or impossible memory source")
				}
			}
		}
	}
}

func TestQueryResourceReportRequiresEveryExecutedBatch(t *testing.T) {
	manifest := []scenario{{"compiled_query_consumer_scaling", "internal/conformance", "TestExample", []string{"zenon-spv"}}}
	base := sampleEvents()
	events := slices.Clone(base[:3])
	for _, name := range []string{"T1", "T16", "T256"} {
		child := "TestExample/" + name
		events = append(events,
			testEvent{Action: "run", Package: base[0].Package, Test: child},
			testEvent{Action: "output", Package: base[0].Package, Test: child, Output: queryResourceMarker + sampleQueryResource(t, name)},
			testEvent{Action: "pass", Package: base[0].Package, Test: child})
	}
	events = append(events, base[5:]...)
	for _, mode := range []string{"complete", "missing", "duplicate", "outside execution", "wrong child", "wrong case", "wrong resource kind"} {
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
				input[4].Output = queryResourceMarker + sampleQueryResource(t, "T16")
			case "wrong case":
				c.cases[0].ID = "compiled_content_scaling"
			case "wrong resource kind":
				input[4].Output = resourceMarker + sampleResource(t, "M1_P1")
			}
			var eventErr error
			for _, event := range input {
				if eventErr = c.event(event); eventErr != nil {
					break
				}
			}
			switch mode {
			case "complete":
				if eventErr != nil || c.finish(true) != "passed" || len(c.cases[0].QueryResources) != 3 || len(c.cases[0].Resources) != 0 {
					t.Fatal("complete consumer measurements lost or mixed with verifier samples")
				}
			case "missing":
				if eventErr != nil || c.finish(true) != "incomplete" {
					t.Fatal("missing consumer measurement reported complete")
				}
			default:
				if eventErr == nil {
					t.Fatal("ambiguous consumer measurement execution accepted")
				}
			}
		})
	}
}
