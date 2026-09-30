package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestRunStateCountBoundStopsBeforeRPCOrPersistence(t *testing.T) {
	anchor, _, _ := chainFixtureRPC(t, 1)
	anchorJSON, err := json.Marshal(anchor)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(fmt.Sprintf(`{"version":1,"genesis":%s,"capacity":%d,"retained_window":[%s"PRIVATE_UNREACHED_ROW"]}`,
		anchorJSON, verify.MaxPersistedHeaders, strings.Repeat("null,", verify.MaxPersistedHeaders)))
	path := tmpStateFile(t)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	var out bytes.Buffer
	saves := 0
	loop := &Loop{
		Multi: fetch.NewMultiClient([]string{server.URL}), StatePath: path,
		Genesis: anchor, Policy: verify.Policy{W: 0}, ShowContext: true, Out: &out,
		SaveState: func(string, verify.HeaderState) error { saves++; return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := loop.Run(ctx); !errors.Is(err, verify.ErrInvalidRetainedState) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("watch did not stop at the decoded header bound: %v", err)
	}
	if requests.Load() != 0 || saves != 0 || out.Len() != 0 {
		t.Fatal("invalid retained window reached RPC, persistence, or startup reporting")
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, after) {
		t.Fatalf("failed startup changed state contents: %v", err)
	}
	if after, err := os.Stat(path); err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
		t.Fatalf("failed startup replaced or changed state metadata: %v", err)
	}
	lock, err := statelock.Acquire(path)
	if err != nil {
		t.Fatalf("failed startup retained writer ownership: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}
