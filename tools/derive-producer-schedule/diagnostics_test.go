package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestScheduleConflictingFrontierHidesEndpoints(t *testing.T) {
	headers, preimages := makeChain(t, 2)
	frontier := headers[1]
	frontier.TimestampUnix++
	signFixtureHeader(&frontier)
	wire := momentumJSON(frontier, preimages[1])
	a := startPeerWithFrontier(t, headers, preimages, nil, wire)
	b := startPeerWithFrontier(t, headers, preimages, nil, wire)
	defer a.Close()
	defer b.Close()
	multi := fetch.NewMultiClient([]string{a.URL + "/PRIVATE_PATH?token=PRIVATE_TOKEN", b.URL + "/PRIVATE_PATH"})
	var progress bytes.Buffer
	schedule, err := deriveSchedule(context.Background(), multi, 99, 1001, 1002, 1, &progress)
	if err == nil || schedule != nil || strings.Contains(err.Error()+progress.String(), "PRIVATE") || !strings.Contains(err.Error(), "peer[1]") {
		t.Fatal("frontier conflict disclosed its endpoint or lost the peer label")
	}
}

func TestScheduleHelpHidesEnvironmentPeers(t *testing.T) {
	t.Setenv("ZENON_SPV_PEERS", "https://PRIVATE_USER:PRIVATE_PASSWORD@private.invalid/PRIVATE_PATH?token=PRIVATE_TOKEN")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()
	err = run([]string{"--help"})
	_ = w.Close()
	raw, readErr := io.ReadAll(r)
	if !errors.Is(err, flag.ErrHelp) || readErr != nil || bytes.Contains(raw, []byte("PRIVATE")) || !bytes.Contains(raw, []byte("-peers")) {
		t.Fatal("help disclosed environment endpoints or lost the peer option")
	}
}
