package main

import (
	"bytes"
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
	for i := range queryResourceObservations {
		record.Observations = append(record.Observations, queryResourceObservation{1000000 + int64(i), memory.PeakRSSBytes, memory.PeakRSSSource})
	}
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
				var points []map[string]json.RawMessage
				if json.Unmarshal(fields["observations"], &points) != nil {
					t.Fatal("sample observations malformed")
				}
				for _, point := range points {
					point["peak_rss_bytes"] = fields["peak_rss_bytes"]
					point["peak_rss_source"] = fields["peak_rss_source"]
				}
				fields["observations"], _ = json.Marshal(points)
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

func TestQueryResourceRepeatedObservationContract(t *testing.T) {
	raw := sampleQueryResource(t, "T1")
	var original map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &original) != nil {
		t.Fatal("sample record malformed")
	}
	for _, mode := range []string{"complete", "order preserved", "missing", "empty", "null series", "short", "long", "null point",
		"missing point field", "duplicate point field", "escaped duplicate", "case alias", "unknown point field", "null elapsed",
		"zero elapsed", "overlong elapsed", "float elapsed", "overflow elapsed", "private elapsed", "null source",
		"private source", "zero peak", "overflow peak", "first elapsed mismatch", "first peak mismatch", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			fields := make(map[string]json.RawMessage)
			for key, value := range original {
				fields[key] = value
			}
			var points []json.RawMessage
			if json.Unmarshal(fields["observations"], &points) != nil {
				t.Fatal("sample observations malformed")
			}
			point := string(points[20])
			switch mode {
			case "order preserved":
				points[1], points[2] = points[2], points[1]
			case "empty":
				points = []json.RawMessage{}
			case "short":
				points = points[:20]
			case "long":
				points = append(points, points[20])
			case "null point":
				points[20] = json.RawMessage("null")
			case "missing point field":
				points[20] = json.RawMessage(strings.Replace(point, `"elapsed_ns":1000020,`, "", 1))
			case "duplicate point field":
				points[20] = json.RawMessage(strings.Replace(point, `"elapsed_ns":`, `"elapsed_ns":1000020,"elapsed_ns":`, 1))
			case "escaped duplicate":
				points[20] = json.RawMessage(strings.Replace(point, `"elapsed_ns":`, `"elapsed_\u006es":1000020,"elapsed_ns":`, 1))
			case "case alias":
				points[20] = json.RawMessage(strings.Replace(point, `"elapsed_ns":`, `"Elapsed_NS":`, 1))
			case "unknown point field":
				points[20] = json.RawMessage(strings.Replace(point, `"elapsed_ns":`, `"path":"PRIVATE_PATH","elapsed_ns":`, 1))
			case "null elapsed", "zero elapsed", "overlong elapsed", "float elapsed", "overflow elapsed", "private elapsed":
				value := map[string]string{"null elapsed": "null", "zero elapsed": "0", "overlong elapsed": "60000000001",
					"float elapsed": "1000020.0", "overflow elapsed": "18446744073709551616", "private elapsed": `"PRIVATE_VALUE"`}[mode]
				points[20] = json.RawMessage(strings.Replace(point, `"elapsed_ns":1000020`, `"elapsed_ns":`+value, 1))
			case "null source", "private source", "zero peak", "overflow peak":
				var p map[string]json.RawMessage
				if json.Unmarshal(points[20], &p) != nil {
					t.Fatal("sample observation malformed")
				}
				switch mode {
				case "null source":
					p["peak_rss_source"] = json.RawMessage("null")
				case "private source":
					p["peak_rss_source"] = json.RawMessage(`"PRIVATE_ENDPOINT"`)
				case "zero peak":
					p["peak_rss_bytes"] = json.RawMessage("0")
				case "overflow peak":
					p["peak_rss_bytes"] = json.RawMessage("18446744073709551616")
				}
				points[20], _ = json.Marshal(p)
			case "first elapsed mismatch":
				fields["elapsed_ns"] = json.RawMessage("1000001")
			case "first peak mismatch":
				fields["peak_rss_bytes"] = json.RawMessage("1048577")
			case "oversized":
				points[20] = json.RawMessage(strings.Repeat(" ", 16<<10) + point)
			}
			fields["observations"], _ = json.Marshal(points)
			switch mode {
			case "missing":
				delete(fields, "observations")
			case "null series":
				fields["observations"] = json.RawMessage("null")
			}
			input, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "oversized" {
				input = append(input, []byte(strings.Repeat(" ", 16<<10))...)
			}
			record, err := parseQueryResource(string(input))
			if mode == "complete" || mode == "order preserved" {
				if err != nil || len(record.Observations) != 21 || record.Observations[20].ElapsedNS != 1000020 ||
					(mode == "order preserved" && record.Observations[1].ElapsedNS != 1000002) {
					t.Fatal("complete ordered consumer observations lost")
				}
			} else if err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("incomplete or malformed consumer observations accepted or echoed")
			}
		})
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

func TestQueryResourceFragmentsRequireCompleteBoundExecution(t *testing.T) {
	manifest := []scenario{{"compiled_query_consumer_scaling", "internal/conformance", "TestExample", []string{"zenon-spv"}}}
	for _, mode := range []string{"1024 byte events", "64 byte events", "single event", "missing final fragment", "closed stream",
		"wrong child", "wrong package", "completion before final fragment", "oversized fragment", "duplicate record", "newline in partial record"} {
		t.Run(mode, func(t *testing.T) {
			base := sampleEvents()
			events := slices.Clone(base[:3])
			for _, name := range []string{"T1", "T16", "T256"} {
				child := "TestExample/" + name
				events = append(events, testEvent{Action: "run", Package: base[0].Package, Test: child})
				line := "    helper.go:1: " + queryResourceMarker + sampleQueryResource(t, name) + "\n"
				chunkSize := 1024
				switch mode {
				case "64 byte events":
					chunkSize = 64
				case "single event":
					chunkSize = len(line)
				}
				var chunks []testEvent
				for start := 0; start < len(line); start += chunkSize {
					end := min(start+chunkSize, len(line))
					chunks = append(chunks, testEvent{Action: "output", Package: base[0].Package, Test: child, Output: line[start:end]})
				}
				if name == "T1" {
					switch mode {
					case "missing final fragment":
						chunks = chunks[:len(chunks)-1]
					case "closed stream":
						events = append(events, chunks[0])
					case "wrong child":
						chunks[len(chunks)-1].Test = "TestExample/T16"
					case "wrong package":
						chunks[len(chunks)-1].Package = modulePath + "/internal/verify"
					case "completion before final fragment":
						chunks = slices.Insert(chunks, 1, testEvent{Action: "pass", Package: base[0].Package, Test: child})
					case "oversized fragment":
						chunks[1].Output = strings.Repeat(" ", queryResourceRecordLimit)
					case "duplicate record":
						chunks = append(chunks, testEvent{Action: "output", Package: base[0].Package, Test: child, Output: line})
					case "newline in partial record":
						chunks[0].Output += "\n"
					}
					if mode == "closed stream" {
						break
					}
				}
				events = append(events, chunks...)
				events = append(events, testEvent{Action: "pass", Package: base[0].Package, Test: child})
			}
			if mode != "closed stream" {
				events = append(events, base[5:]...)
			}
			var stream bytes.Buffer
			for _, event := range events {
				if json.NewEncoder(&stream).Encode(event) != nil {
					t.Fatal("event encoding failed")
				}
			}
			c := newCollector(manifest)
			err := c.read(&stream)
			switch mode {
			case "1024 byte events", "64 byte events", "single event":
				if err != nil || c.finish(true) != "passed" || len(c.queryFragments) != 0 || len(c.cases[0].QueryResources) != 3 {
					t.Fatal("complete bounded fragmented observations were lost")
				}
				for _, sample := range c.cases[0].QueryResources {
					if len(sample.Observations) != 21 || sample.Observations[20].ElapsedNS != 1000020 {
						t.Fatal("fragment assembly changed observation order or completeness")
					}
				}
			case "closed stream":
				if err != nil || c.finish(true) != "incomplete" {
					t.Fatal("unfinished event stream reported complete")
				}
			default:
				if err == nil || c.finish(true) == "passed" {
					t.Fatal("invalid or misbound resource fragments accepted")
				}
			}
		})
	}
}
