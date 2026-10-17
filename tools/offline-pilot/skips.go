package main

import (
	"errors"
	"runtime"
	"strings"
)

const skipMarker = "offline-pilot-skip "
const skipMarkerLimit = 256
const skipRecordLimit = 256

type skipRecord struct {
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"`
	Ordinal  int    `json:"ordinal"`
	Control  string `json:"control"`
	Reason   string `json:"reason"`
}

type skipLedger struct {
	SchemaVersion int          `json:"schema_version"`
	Coverage      string       `json:"coverage"`
	Records       []skipRecord `json:"records"`
}

type skipSlot struct {
	scenario, test, control, reason string
	windowsOnly                     bool
}

// Only source-owned identifiers may cross the report boundary. Dynamic test
// names, diagnostic text and hashes of private names are never ledger fields.
var sourceSkipSlots = []skipSlot{
	{"collect_query_resume", "TestCompiledCLIQueryWorkflow/accepted_headers_with_failed_save_exit_nonzero", "state_save_permission_probe", "readonly_directory_writable", false},
	{"consumer_input_fifo", "TestConsumerInputFIFOOpenIsBounded/selected", "consumer_fifo_selected", "native_fifo_nofollow_unavailable", true},
	{"consumer_input_fifo", "TestConsumerInputFIFOOpenIsBounded/replacement", "consumer_fifo_replacement", "native_fifo_nofollow_unavailable", true},
	{"consumer_input_fifo", "TestConsumerInputFIFOOpenIsBounded/symlink_replacement", "consumer_fifo_symlink_replacement", "native_fifo_nofollow_unavailable", true},
	{"state_inspection", "TestCompiledCLIStateInspection/nonregular_FIFO", "state_input_fifo", "native_fifo_unavailable", true},
}

type skipFragment struct {
	slot    skipSlot
	payload string
}

type skipCollector struct {
	platform  string
	pending   map[string]skipSlot
	fragments map[string]skipFragment
	seen      map[string]bool
	ledger    skipLedger
}

func newSkipCollector() *skipCollector {
	return newSkipCollectorForPlatform(runtime.GOOS)
}

func newSkipCollectorForPlatform(platform string) *skipCollector {
	return &skipCollector{
		platform:  platform,
		pending:   make(map[string]skipSlot),
		fragments: make(map[string]skipFragment),
		seen:      make(map[string]bool),
		ledger:    skipLedger{SchemaVersion: 1, Coverage: "complete", Records: []skipRecord{}},
	}
}

func skipPlatformSupported(platform string) bool {
	return platform == "linux" || platform == "darwin" || platform == "windows"
}

func skipSlotAllowed(slot skipSlot, platform string) bool {
	return skipPlatformSupported(platform) && (!slot.windowsOnly || platform == "windows")
}

func skipSlotForTest(scenario, test, platform string) (skipSlot, bool) {
	for _, slot := range sourceSkipSlots {
		if slot.scenario == scenario && slot.test == test && skipSlotAllowed(slot, platform) {
			return slot, true
		}
	}
	return skipSlot{}, false
}

func skipSlotForControl(scenario, control, platform string) (skipSlot, bool) {
	for _, slot := range sourceSkipSlots {
		if slot.scenario == scenario && slot.control == control && skipSlotAllowed(slot, platform) {
			return slot, true
		}
	}
	return skipSlot{}, false
}

func skipPayload(slot skipSlot) string {
	return "v1 control=" + slot.control + " reason=" + slot.reason + "\n"
}

// A marker is evidence only for the same active source-owned test. It must
// still be followed by that test's actual skip completion.
func (s *skipCollector) output(scenario, test, key, raw string, active bool) (bool, error) {
	if fragment, pending := s.fragments[key]; pending {
		if !active || len(raw) > skipMarkerLimit-len(skipMarker)-len(fragment.payload) {
			return true, errors.New("invalid skip marker fragment")
		}
		return true, s.accept(key, fragment.slot, fragment.payload+raw)
	}
	_, payload, marked := strings.Cut(raw, skipMarker)
	if !marked {
		return false, nil
	}
	if !active || strings.Count(raw, skipMarker) != 1 {
		return true, errors.New("invalid skip marker")
	}
	if _, pending := s.pending[key]; pending {
		return true, errors.New("duplicate skip marker")
	}
	slot, expected := skipSlotForTest(scenario, test, s.platform)
	if !expected {
		return true, errors.New("unexpected skip marker")
	}
	return true, s.accept(key, slot, payload)
}

func (s *skipCollector) accept(key string, slot skipSlot, payload string) error {
	expected := skipPayload(slot)
	if len(skipMarker)+len(payload) > skipMarkerLimit || !strings.HasPrefix(expected, payload) {
		return errors.New("invalid skip marker")
	}
	if payload != expected {
		s.fragments[key] = skipFragment{slot: slot, payload: payload}
		return nil
	}
	delete(s.fragments, key)
	s.pending[key] = slot
	return nil
}

func (s *skipCollector) complete(scenario, key, action string, nested bool) error {
	if _, pending := s.fragments[key]; pending {
		return errors.New("unfinished skip marker")
	}
	slot, claimed := s.pending[key]
	if claimed && action != "skip" {
		return errors.New("skip marker without skip completion")
	}
	if action != "skip" {
		return nil
	}
	if len(s.ledger.Records) >= skipRecordLimit {
		return errors.New("skip ledger exceeded limits")
	}
	record := skipRecord{
		Scenario: scenario, Scope: "root", Ordinal: len(s.ledger.Records) + 1,
		Control: "unknown", Reason: "unreported",
	}
	if nested {
		record.Scope = "child"
	}
	if claimed {
		identity := scenario + "/" + slot.control
		if !nested || slot.scenario != scenario || s.seen[identity] {
			return errors.New("inconsistent skip completion")
		}
		record.Control, record.Reason = slot.control, slot.reason
		s.seen[identity] = true
		delete(s.pending, key)
	} else {
		s.ledger.Coverage = "unknown"
	}
	s.ledger.Records = append(s.ledger.Records, record)
	return nil
}

func (s *skipCollector) unfinished() bool {
	return len(s.pending) != 0 || len(s.fragments) != 0
}

func (s *skipCollector) snapshot() *skipLedger {
	result := s.ledger
	result.Records = make([]skipRecord, len(s.ledger.Records))
	copy(result.Records, s.ledger.Records)
	return &result
}

// New candidates require complete diagnostic coverage. Historical version-1
// reports remain readable through the caller's explicit compatibility branch.
func validateSkipLedger(ledger *skipLedger, cases []caseResult, platform string, requireComplete bool) error {
	fail := func() error { return errors.New("invalid skip ledger") }
	if ledger == nil || ledger.SchemaVersion != 1 || ledger.Records == nil ||
		len(ledger.Records) > skipRecordLimit || !skipPlatformSupported(platform) ||
		(ledger.Coverage != "complete" && ledger.Coverage != "unknown") || len(cases) == 0 || len(cases) > 256 {
		return fail()
	}
	selected := make(map[string]caseResult)
	for _, result := range cases {
		if _, duplicate := selected[result.ID]; duplicate || result.Skipped < 0 {
			return fail()
		}
		selected[result.ID] = result
	}
	children, roots, seen := make(map[string]int), make(map[string]int), make(map[string]bool)
	unknown := false
	for index, record := range ledger.Records {
		result, expected := selected[record.Scenario]
		if !expected || record.Ordinal != index+1 || (record.Scope != "child" && record.Scope != "root") {
			return fail()
		}
		if record.Scope == "child" {
			children[record.Scenario]++
		} else {
			roots[record.Scenario]++
		}
		if record.Control == "unknown" {
			if record.Reason != "unreported" {
				return fail()
			}
			unknown = true
			continue
		}
		slot, allowed := skipSlotForControl(record.Scenario, record.Control, platform)
		root, _, _ := strings.Cut(slot.test, "/")
		identity := record.Scenario + "/" + record.Control
		if !allowed || record.Scope != "child" || record.Reason != slot.reason || result.Test != root || seen[identity] {
			return fail()
		}
		seen[identity] = true
	}
	for _, result := range cases {
		expectedRoots := 0
		if result.Status == "skipped" {
			expectedRoots = 1
		}
		if children[result.ID] != result.Skipped || roots[result.ID] != expectedRoots {
			return fail()
		}
	}
	if (ledger.Coverage == "unknown") != unknown || (requireComplete && unknown) {
		return fail()
	}
	return nil
}
