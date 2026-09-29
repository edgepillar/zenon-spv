package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/fetch"
)

func TestScheduleDiagnosticsDoNotPrintEndpoints(t *testing.T) {
	const marker = "private-peer-marker"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, marker)
	}))
	defer server.Close()
	multi := fetch.NewMultiClient([]string{server.URL + "/" + marker + "?token=1", server.URL + "/" + marker + "?token=2"})
	var progress bytes.Buffer
	schedule, err := deriveSchedule(context.Background(), multi, 3, 2, 2, 1, &progress)
	if err == nil || schedule != nil {
		t.Fatal("failed local RPC returned a schedule")
	}
	text := progress.String() + err.Error()
	if strings.Contains(text, marker) || strings.Contains(text, server.URL) || !strings.Contains(text, "peer[1]") || !strings.Contains(text, "503") {
		t.Fatal("diagnostics disclosed endpoint data or lost useful status")
	}
}
