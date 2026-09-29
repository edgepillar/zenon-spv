package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckpointDiagnosticsDoNotPrintEndpoints(t *testing.T) {
	const marker = "private-peer-marker"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, marker)
	}))
	defer server.Close()
	output, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	defer func() { os.Stdout = previous; _ = output.Close() }()
	os.Stdout = output
	peers := server.URL + "/" + marker + "?token=1," + server.URL + "/" + marker + "?token=2"
	err = run([]string{"--peers", peers, "--heights", "42"})
	os.Stdout = previous
	raw, readErr := os.ReadFile(output.Name())
	if err == nil || readErr != nil {
		t.Fatal("expected a failed local fetch with captured diagnostics")
	}
	text := string(raw) + err.Error()
	if strings.Contains(text, marker) || strings.Contains(text, server.URL) || !strings.Contains(text, "peer[1]") || !strings.Contains(text, "peer[2]") || !strings.Contains(text, "503") {
		t.Fatal("diagnostics disclosed endpoint data or lost useful status")
	}
}
