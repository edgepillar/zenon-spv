package statelock

import "testing"

func TestWindowsStateNameNamespace(t *testing.T) {
	for _, name := range []string{"state.json", "trusted-state", "STATE.JSON"} {
		if !stateNameSupported(name) {
			t.Fatalf("ordinary filename refused: %q", name)
		}
	}
	for _, name := range []string{"state.json.", "state.json ", "state.lock.", "STATE~1.JSON", "state.json:stream", "NUL", "CON", "COM1.txt"} {
		if stateNameSupported(name) {
			t.Fatalf("ambiguous filename accepted: %q", name)
		}
	}
}
