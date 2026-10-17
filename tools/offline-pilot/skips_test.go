package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func skipFixture(slot skipSlot) (scenario, []testEvent) {
	root, _, _ := strings.Cut(slot.test, "/")
	selected := scenario{ID: slot.scenario, Package: "internal/conformance", Test: root}
	if slot.scenario == "consumer_input_fifo" {
		selected.Package = "tools/consume-query-report"
	}
	pkg := modulePath + "/" + selected.Package
	return selected, []testEvent{
		{Action: "start", Package: pkg},
		{Action: "run", Package: pkg, Test: root},
		{Action: "run", Package: pkg, Test: slot.test},
		{Action: "output", Package: pkg, Test: slot.test, Output: "    PRIVATE_SOURCE_PATH:10: " + skipMarker + skipPayload(slot)},
		{Action: "skip", Package: pkg, Test: slot.test},
		{Action: "pass", Package: pkg, Test: root},
		{Action: "pass", Package: pkg},
	}
}

func collectSkipFixture(t *testing.T, selected scenario, platform string, events []testEvent) (*eventCollector, error) {
	t.Helper()
	var input bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&input).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	collector := newCollector([]scenario{selected})
	collector.skips = newSkipCollectorForPlatform(platform)
	return collector, collector.read(&input)
}

func assertSkipPrivacy(t *testing.T, ledger *skipLedger) {
	t.Helper()
	raw, err := json.Marshal(ledger)
	if err != nil || bytes.Contains(raw, []byte("PRIVATE")) ||
		bytes.Contains(raw, []byte("sha256")) || bytes.Contains(raw, []byte("test_name")) {
		t.Fatal("skip ledger disclosed diagnostics, dynamic identities or their hashes")
	}
}

func TestOfflinePilotSkipLedgerKnownCompletion(t *testing.T) {
	for _, platform := range []string{"linux", "darwin", "windows"} {
		for _, slot := range sourceSkipSlots {
			if !skipSlotAllowed(slot, platform) {
				continue
			}
			t.Run(platform+"/"+slot.control, func(t *testing.T) {
				selected, events := skipFixture(slot)
				collector, err := collectSkipFixture(t, selected, platform, events)
				if err != nil || collector.finish(true) != "passed_with_skips" {
					t.Fatal("complete skip execution was lost")
				}
				ledger := collector.skips.snapshot()
				if ledger.SchemaVersion != 1 || ledger.Coverage != "complete" || len(ledger.Records) != 1 {
					t.Fatal("known completion did not produce one complete ledger entry")
				}
				want := skipRecord{Scenario: slot.scenario, Scope: "child", Ordinal: 1, Control: slot.control, Reason: slot.reason}
				if ledger.Records[0] != want || collector.cases[0].Skipped != 1 ||
					validateSkipLedger(ledger, collector.cases, platform, true) != nil {
					t.Fatal("skip entry lost its actual scenario, count or source-owned reason")
				}
				assertSkipPrivacy(t, ledger)
			})
		}
	}
}

func TestOfflinePilotSkipLedgerUnknownRemainsExplicit(t *testing.T) {
	for _, rootSkip := range []bool{false, true} {
		t.Run(fmt.Sprint(rootSkip), func(t *testing.T) {
			selected := scenario{ID: "sample", Package: "internal/conformance", Test: "TestExample"}
			pkg := modulePath + "/" + selected.Package
			events := []testEvent{{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: selected.Test}}
			scope, status := "root", "incomplete"
			if rootSkip {
				events = append(events, testEvent{Action: "output", Package: pkg, Test: selected.Test, Output: "PRIVATE_PATH PRIVATE_ENDPOINT PRIVATE_CREDENTIAL\n"},
					testEvent{Action: "skip", Package: pkg, Test: selected.Test})
			} else {
				scope, status = "child", "passed_with_skips"
				child := selected.Test + "/PRIVATE_CHILD"
				events = append(events, testEvent{Action: "run", Package: pkg, Test: child},
					testEvent{Action: "output", Package: pkg, Test: child, Output: "PRIVATE_PATH PRIVATE_ENDPOINT PRIVATE_CREDENTIAL\n"},
					testEvent{Action: "skip", Package: pkg, Test: child}, testEvent{Action: "pass", Package: pkg, Test: selected.Test})
			}
			events = append(events, testEvent{Action: "pass", Package: pkg})
			collector, err := collectSkipFixture(t, selected, "linux", events)
			if err != nil || collector.finish(true) != status {
				t.Fatal("unknown or root skip changed execution accounting")
			}
			ledger := collector.skips.snapshot()
			if ledger.Coverage != "unknown" || len(ledger.Records) != 1 ||
				ledger.Records[0] != (skipRecord{Scenario: "sample", Scope: scope, Ordinal: 1, Control: "unknown", Reason: "unreported"}) {
				t.Fatal("unknown skip was inferred or hidden")
			}
			if validateSkipLedger(ledger, collector.cases, "linux", false) != nil ||
				validateSkipLedger(ledger, collector.cases, "linux", true) == nil {
				t.Fatal("unknown coverage was confused with complete qualification")
			}
			assertSkipPrivacy(t, ledger)
		})
	}
}

func TestOfflinePilotSkipLedgerMarkerBinding(t *testing.T) {
	for _, mode := range []string{
		"inactive", "wrong slot", "wrong scenario", "wrong platform", "duplicate marker",
		"wrong version", "unknown control", "unknown reason", "trailing diagnostic",
		"pass after marker", "parent marker", "oversized", "unfinished fragment",
	} {
		t.Run(mode, func(t *testing.T) {
			slot := sourceSkipSlots[1]
			selected, events := skipFixture(slot)
			platform := "windows"
			switch mode {
			case "inactive":
				events = append(events[:2], events[3:]...)
			case "wrong slot":
				for i := 2; i <= 4; i++ {
					events[i].Test = selected.Test + "/PRIVATE_CHILD"
				}
			case "wrong scenario":
				selected.ID = "sample"
			case "wrong platform":
				platform = "darwin"
			case "duplicate marker":
				events = append(events[:4], append([]testEvent{events[3]}, events[4:]...)...)
			case "wrong version":
				events[3].Output = skipMarker + strings.Replace(skipPayload(slot), "v1 ", "v2 ", 1)
			case "unknown control":
				events[3].Output = skipMarker + "v1 control=PRIVATE_CONTROL reason=" + slot.reason + "\n"
			case "unknown reason":
				events[3].Output = skipMarker + "v1 control=" + slot.control + " reason=PRIVATE_REASON\n"
			case "trailing diagnostic":
				events[3].Output += "PRIVATE_DIAGNOSTIC\n"
			case "pass after marker":
				events[4].Action = "pass"
			case "parent marker":
				events[3].Test = selected.Test
			case "oversized":
				events[3].Output = skipMarker + strings.Repeat("PRIVATE", skipMarkerLimit)
			case "unfinished fragment":
				events[3].Output = strings.TrimSuffix(events[3].Output, "\n")
			}
			_, err := collectSkipFixture(t, selected, platform, events)
			if err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("invalid marker was accepted or its input was disclosed")
			}
		})
	}
}

func TestOfflinePilotSkipLedgerFragmentsAndInterruption(t *testing.T) {
	slot := sourceSkipSlots[1]
	payload := skipPayload(slot)
	for _, split := range []int{1, 19, len(payload) - 1} {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			selected, events := skipFixture(slot)
			events[3].Output = skipMarker + payload[:split]
			continuation := events[3]
			continuation.Output = payload[split:]
			events = append(events[:4], append([]testEvent{continuation}, events[4:]...)...)
			collector, err := collectSkipFixture(t, selected, "windows", events)
			if err != nil || collector.finish(true) != "passed_with_skips" || collector.skips.unfinished() ||
				validateSkipLedger(collector.skips.snapshot(), collector.cases, "windows", true) != nil {
				t.Fatal("bounded same-test marker fragments were not joined")
			}
		})
	}
	t.Run("interruption", func(t *testing.T) {
		selected, events := skipFixture(slot)
		collector, err := collectSkipFixture(t, selected, "windows", events[:4])
		if err != nil || collector.finish(true) != "incomplete" || !collector.skips.unfinished() ||
			len(collector.skips.snapshot().Records) != 0 {
			t.Fatal("marker without actual completion fabricated a skip")
		}
	})
	t.Run("oversized continuation", func(t *testing.T) {
		selected, events := skipFixture(slot)
		events[3].Output = skipMarker + payload[:1]
		continuation := events[3]
		continuation.Output = strings.Repeat("PRIVATE", skipMarkerLimit)
		events = append(events[:4], append([]testEvent{continuation}, events[4:]...)...)
		_, err := collectSkipFixture(t, selected, "windows", events)
		if err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("over-boundary continuation was accepted or disclosed")
		}
	})
}

func TestOfflinePilotSkipLedgerBoundsAndSnapshots(t *testing.T) {
	selected := scenario{ID: "sample", Package: "internal/conformance", Test: "TestExample"}
	pkg := modulePath + "/" + selected.Package
	for _, count := range []int{skipRecordLimit, skipRecordLimit + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			events := []testEvent{{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: selected.Test}}
			for index := 0; index < count; index++ {
				child := fmt.Sprintf("%s/PRIVATE_%d", selected.Test, index)
				events = append(events, testEvent{Action: "run", Package: pkg, Test: child},
					testEvent{Action: "skip", Package: pkg, Test: child})
			}
			events = append(events, testEvent{Action: "pass", Package: pkg, Test: selected.Test}, testEvent{Action: "pass", Package: pkg})
			collector, err := collectSkipFixture(t, selected, "linux", events)
			if count > skipRecordLimit {
				if err == nil || collector.finish(false) != "failed" || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("over-boundary skip count was not refused")
				}
				return
			}
			if err != nil || collector.finish(true) != "passed_with_skips" ||
				validateSkipLedger(collector.skips.snapshot(), collector.cases, "linux", false) != nil {
				t.Fatal("exact-boundary unknown ledger was lost")
			}
			ledger := collector.skips.snapshot()
			ledger.Records[0].Control = "PRIVATE_MUTATION"
			fresh := collector.skips.snapshot()
			if fresh.Records[0].Control != "unknown" {
				t.Fatal("snapshot mutation changed collected evidence")
			}
			assertSkipPrivacy(t, fresh)
		})
	}
	empty := newSkipCollectorForPlatform("linux").snapshot()
	raw, err := json.Marshal(empty)
	if err != nil || empty.Records == nil || !bytes.Contains(raw, []byte("\"records\":[]")) {
		t.Fatal("empty ledger lost explicit zero-skip coverage")
	}
}

func TestOfflinePilotSkipLedgerValidation(t *testing.T) {
	for _, mode := range []string{
		"nil ledger", "wrong version", "nil records", "wrong coverage", "missing entry", "wrong ordinal",
		"wrong scope", "unknown control", "wrong reason", "wrong scenario", "wrong root",
		"duplicate control", "wrong skip count", "duplicate scenario", "empty scenarios", "wrong platform",
	} {
		t.Run(mode, func(t *testing.T) {
			slot := sourceSkipSlots[1]
			selected, events := skipFixture(slot)
			collector, err := collectSkipFixture(t, selected, "windows", events)
			if err != nil || collector.finish(true) != "passed_with_skips" {
				t.Fatal("invalid control setup")
			}
			ledger, cases, platform := collector.skips.snapshot(), collector.cases, "windows"
			switch mode {
			case "nil ledger":
				ledger = nil
			case "wrong version":
				ledger.SchemaVersion = 0
			case "nil records":
				ledger.Records = nil
			case "wrong coverage":
				ledger.Coverage = "unknown"
			case "missing entry":
				ledger.Records = []skipRecord{}
			case "wrong ordinal":
				ledger.Records[0].Ordinal = 0
			case "wrong scope":
				ledger.Records[0].Scope = "PRIVATE_SCOPE"
			case "unknown control":
				ledger.Records[0].Control = "PRIVATE_CONTROL"
			case "wrong reason":
				ledger.Records[0].Reason = "PRIVATE_REASON"
			case "wrong scenario":
				ledger.Records[0].Scenario = "PRIVATE_SCENARIO"
			case "wrong root":
				cases[0].Test = "TestPrivate"
			case "duplicate control":
				ledger.Records = append(ledger.Records, ledger.Records[0])
				ledger.Records[1].Ordinal = 2
				cases[0].Skipped = 2
			case "wrong skip count":
				cases[0].Skipped = 0
			case "duplicate scenario":
				cases = append(cases, cases[0])
			case "empty scenarios":
				cases = nil
			case "wrong platform":
				platform = "darwin"
			}
			if err := validateSkipLedger(ledger, cases, platform, true); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("inconsistent ledger was accepted or disclosed")
			}
		})
	}
}

func TestOfflinePilotSkipLedgerCandidateCompatibility(t *testing.T) {
	for _, mode := range []string{"legacy", "version2 empty", "version2 known", "version2 missing", "version2 unknown", "legacy with ledger"} {
		t.Run(mode, func(t *testing.T) {
			dir, report := sampleCandidate(t)
			if mode != "legacy" {
				report.SkipLedger = newSkipCollectorForPlatform(report.Runner.OS).snapshot()
			}
			if mode != "legacy" && mode != "legacy with ledger" {
				report.SchemaVersion = 2
			}
			switch mode {
			case "version2 known":
				slot := sourceSkipSlots[0]
				report.Status = "passed_with_skips"
				for i := range report.Cases {
					if report.Cases[i].ID == slot.scenario {
						report.Cases[i].Skipped, report.Cases[i].Status = 1, "passed_with_skips"
					}
				}
				report.SkipLedger.Records = []skipRecord{{Scenario: slot.scenario, Scope: "child", Ordinal: 1, Control: slot.control, Reason: slot.reason}}
			case "version2 missing":
				report.SkipLedger = nil
			case "version2 unknown":
				report.Status = "passed_with_skips"
				report.Cases[0].Status, report.Cases[0].Skipped = "passed_with_skips", 1
				report.SkipLedger.Coverage = "unknown"
				report.SkipLedger.Records = []skipRecord{{Scenario: report.Cases[0].ID, Scope: "child", Ordinal: 1, Control: "unknown", Reason: "unreported"}}
			}
			err := finalizeCandidate(dir, report, candidateReportBytes(t, report))
			accepted := mode == "legacy" || mode == "version2 empty" || mode == "version2 known"
			if accepted {
				if err != nil {
					t.Fatal("compatible complete candidate was refused")
				}
			} else {
				if err == nil || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("candidate accepted incomplete or ambiguous skip diagnostics")
				}
				if _, err := os.Stat(filepath.Join(dir, "manifest.json")); !os.IsNotExist(err) {
					t.Fatal("refused ledger produced candidate completion metadata")
				}
			}
		})
	}
}
