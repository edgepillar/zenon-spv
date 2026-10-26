package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type eofTestReader struct {
	raw []byte
	err error
}

func (r *eofTestReader) Read(out []byte) (int, error) {
	n := copy(out, r.raw)
	r.raw = r.raw[n:]
	if len(r.raw) == 0 {
		return n, r.err
	}
	return n, nil
}

// A promoted WriterTo must not bypass Read's EOF observation or capped Write.
type eofCopyShortcut struct{ *strings.Reader }

func (r eofCopyShortcut) WriteTo(io.Writer) (int64, error) {
	return 0, errors.New("PRIVATE_COPY_SHORTCUT")
}

func TestObservationStreamEOF(t *testing.T) {
	readFailure := errors.New("PRIVATE_READ_ERROR")
	tests := []struct {
		name        string
		input       io.Reader
		destination io.Writer
		ok          bool
	}{
		{"empty", strings.NewReader(""), nil, true},
		{"ordinary", strings.NewReader("abc"), nil, true},
		{"data_and_EOF", &eofTestReader{[]byte("abc"), io.EOF}, nil, true},
		{"copy_shortcut", eofCopyShortcut{strings.NewReader("abc")}, nil, true},
		{"read_error", &eofTestReader{[]byte("abc"), readFailure}, nil, false},
		{"output_cap", strings.NewReader(strings.Repeat("x", 33)), nil, false},
		{"write_error", strings.NewReader("abc"), eofFailedWriter{}, false},
		{"short_write", strings.NewReader("abc"), shortObserverWriter{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cancelled := false
			out := &boundedOutput{limit: 32, retain: true, destination: tc.destination, cancel: func() { cancelled = true }}
			_, err := out.ReadFrom(tc.input)
			if (err == nil) != tc.ok || out.readEOF != tc.ok || out.buffer.Len() > 32 {
				t.Fatal("copy lost capped Write or real EOF completion")
			}
			if tc.name == "output_cap" && (!cancelled || !out.exceeded || out.observed != 33) {
				t.Fatal("ReaderFrom bypassed the output cap")
			}
			if tc.destination != nil && (!cancelled || !out.writeFailed || out.buffer.Len() != 0) {
				t.Fatal("destination failure acquired EOF-complete retained output")
			}
			if tc.ok && out.buffer.String() != "abc" && tc.name != "empty" {
				t.Fatal("EOF copy changed payload bytes")
			}
		})
	}
	// Reuse must clear a previous EOF certificate before a later failed read.
	out := &boundedOutput{limit: 32, cancel: func() {}}
	if _, err := out.ReadFrom(strings.NewReader("abc")); err != nil || !out.readEOF || out.buffer.Len() != 0 {
		t.Fatal("diagnostic copy lost EOF or retained private bytes")
	}
	if _, err := out.ReadFrom(&eofTestReader{nil, readFailure}); err == nil || out.readEOF {
		t.Fatal("later failed read retained an earlier EOF certificate")
	}
	t.Log("observer-stream-eof-copy-controls {\"schema_version\":1,\"copy_controls\":9,\"real_EOF_complete\":4,\"copy_refusals\":5,\"copy_shortcuts_bypassed\":true,\"stream_cap_bytes\":32}")
}

type shortObserverWriter struct{}

func (shortObserverWriter) Write(raw []byte) (int, error) { return len(raw) - 1, nil }

type eofFailedWriter struct{}

func (eofFailedWriter) Write([]byte) (int, error) { return 0, errors.New("PRIVATE_DESTINATION_ERROR") }

func TestObservationEOFCompletionGate(t *testing.T) {
	readFailure := errors.New("PRIVATE_TERMINAL_READ_ERROR")
	wrapped := errors.Join(readFailure, exec.ErrWaitDelay)
	tests := []struct {
		name                 string
		err                  error
		stdoutEOF, stderrEOF bool
		ok                   bool
	}{
		{"ordinary_complete", nil, true, true, true},
		{"timer_both_EOF", exec.ErrWaitDelay, true, true, true},
		{"timer_stdout_incomplete", exec.ErrWaitDelay, false, true, false},
		{"timer_stderr_incomplete", exec.ErrWaitDelay, true, false, false},
		{"timer_both_incomplete", exec.ErrWaitDelay, false, false, false},
		{"nil_missing_EOF", nil, false, true, false},
		{"different_error", readFailure, true, true, false},
		{"wrapped_timer_error", wrapped, true, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := joinedCopyError(tc.err, &boundedOutput{readEOF: tc.stdoutEOF}, &boundedOutput{readEOF: tc.stderrEOF})
			if (err == nil) != tc.ok || (tc.err != nil && tc.err != exec.ErrWaitDelay && err != tc.err) {
				t.Fatal("terminal gate accepted missing EOF or discarded another error")
			}
		})
	}
	t.Log("observer-stream-eof-gate-controls {\"schema_version\":1,\"terminal_controls\":8,\"EOF_complete_acceptances\":2,\"refusals\":6,\"exact_timer_error_only\":true,\"one_second_join_limit_unchanged\":true}")
	t.Setenv("ZENON_OBSERVER_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate native EOF control helper")
	}
	for _, mode := range []string{"success", "failed"} {
		result := runProcess(context.Background(), binary, []string{"-test.run=^TestObservationProcessHelper$", "--", mode}, 32, 5*time.Second)
		if !result.stdoutEOF || !result.stderrEOF || result.ExitCode == nil || bytes.Contains(result.stdout, []byte("PRIVATE")) {
			t.Fatal("native process did not retain joined, private EOF evidence")
		}
		encoded, encodeErr := json.Marshal(result.observation)
		var fields map[string]json.RawMessage
		if encodeErr != nil || json.Unmarshal(encoded, &fields) != nil || len(fields) != 4 || fields["incomplete_output"] != nil {
			t.Fatal("EOF-complete observation changed the four-field child record")
		}
		if mode == "success" && (result.code != 0 || result.category != "" || *result.ExitCode != 0 || string(result.stdout) != "ACCEPT\n") {
			t.Fatal("EOF-complete successful child was refused")
		}
		if mode == "failed" && (result.code != 2 || result.category != "process_failure" || *result.ExitCode != 70) {
			t.Fatal("EOF-complete failed child acquired success")
		}
		record, err := json.Marshal(struct {
			Name         string `json:"name"`
			ChildExit    int64  `json:"actual_child_exit"`
			ObserverExit int    `json:"observer_exit"`
			Category     string `json:"category"`
			StdoutEOF    bool   `json:"stdout_EOF"`
			StderrEOF    bool   `json:"stderr_EOF"`
		}{mode, *result.ExitCode, result.code, result.category, result.stdoutEOF, result.stderrEOF})
		if err != nil {
			t.Fatal("cannot encode fixed native EOF evidence")
		}
		t.Logf("observer-stream-eof-child-observation %s", record)
	}
}
