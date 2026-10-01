package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestCompiledCLIStateWriterExclusion(t *testing.T) {
	bin := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	c, bundle := contractBatchBundle(t)
	dir := t.TempDir()
	anchor := writeCLIJSON(t, dir, "anchor.json", c.Chain.Anchor)
	statePath := filepath.Join(dir, "state.json")
	headers := bundle.Headers
	bundle.Headers = headers[:6]
	seed := writeCLIJSON(t, dir, "seed.json", bundle)
	bundle.Headers = headers[6:]
	extension := writeCLIJSON(t, dir, "extension.json", bundle)
	bundle.Headers = nil
	proofPath := writeCLIJSON(t, dir, "proof.json", bundle)
	common := []string{"--json", "--genesis-config", anchor, "--state", statePath}
	checkProcessReport(t, runQueryCLI(t, bin, append([]string{"verify-headers"}, append(slices.Clone(common), seed)...)...), 0, "ACCEPT")

	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	var requests atomic.Int64
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var request struct {
			ID     json.RawMessage
			Method string
			Params []uint64
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var result any
		switch request.Method {
		case "ledger.getFrontierMomentum":
			enteredOnce.Do(func() { close(entered) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			result = c.Chain.Vectors[6].Momentum // height 4007, safety margin 1
		case "ledger.getMomentumsByHeight":
			if !slices.Equal(request.Params, []uint64{4006, 1}) {
				t.Error("unexpected watch target")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			result = map[string]any{"list": []json.RawMessage{c.Chain.Vectors[5].Momentum}}
		default:
			t.Error("unexpected watch RPC method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	watchArgs := []string{"watch", "--rpc", server.URL, "--genesis-config", anchor, "--state", statePath, "--safety-margin", "1", "--interval", "1h"}
	watch := exec.CommandContext(ctx, bin, watchArgs...)
	watch.Env, watch.Stdout = queryCLIEnvironment(), io.Discard
	watch.WaitDelay = time.Second
	tick := &writerTickLog{ticked: make(chan struct{})}
	watch.Stderr = tick
	if err := watch.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unblock(); _ = watch.Process.Kill(); _ = watch.Wait() })
	select {
	case <-entered: // Watch has loaded tip 4006 and is holding the writer lock.
	case <-ctx.Done():
		t.Fatal("watch never reached the synchronized frontier request")
	}
	before := readCLIFile(t, statePath)
	blocked := checkProcessReport(t, runQueryCLI(t, bin, append([]string{"verify-headers"}, append(slices.Clone(common), extension)...)...), 70, "")
	if blocked.Error == nil || blocked.Error.Stage != "state_lock" || len(blocked.Results) != 0 || blocked.Persistence != "not_attempted" {
		t.Fatal("second writer verified or saved against the watch-owned state")
	}
	otherWatch := runQueryCLI(t, bin, watchArgs...)
	if otherWatch.code != 70 || !bytes.Contains(otherWatch.stderr, []byte("already has an active writer")) || requests.Load() != 1 {
		t.Fatal("second watch reached RPC before rejecting state ownership")
	}
	oneStep := runQueryCLI(t, bin, append(slices.Clone(watchArgs), "--once", "--json")...)
	if oneStep.code != 70 || len(oneStep.stdout) != 0 || string(oneStep.stderr) != "watch: operation failed\n" || requests.Load() != 1 {
		t.Fatal("single-step watch bypassed writer ownership or exposed a private setup error")
	}
	query := append([]string{"verify-commitment"}, append(slices.Clone(common), "--retained-only", proofPath)...)
	readOnly := checkProcessReport(t, runQueryCLI(t, bin, query...), 2, "REFUSED")
	if readOnly.Error != nil || readOnly.Persistence != "read_only" || len(readOnly.Results) != 5 || readOnly.Results[0].Reason != "ReasonInsufficientFinality" {
		t.Fatal("read-only query was blocked instead of applying its depth policy")
	}
	if !bytes.Equal(before, readCLIFile(t, statePath)) {
		t.Fatal("overlapping commands changed state before the held watch tick")
	}
	unblock()
	select {
	case <-tick.ticked:
	case <-ctx.Done():
		t.Fatal("watch never completed its caught-up tick")
	}
	var stopErr error
	if runtime.GOOS == "windows" {
		stopErr = watch.Process.Kill()
	} else {
		stopErr = watch.Process.Signal(os.Interrupt)
	}
	if stopErr != nil {
		t.Fatal(stopErr)
	}
	err := watch.Wait()
	if runtime.GOOS != "windows" && err != nil || ctx.Err() != nil {
		t.Fatalf("watch failed to shut down: %v", err)
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
	}
	resumed, err := verify.LoadTrustedState(statePath, c.Chain.Anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
	tip, ok := resumed.Tip()
	if err != nil || !ok || tip.Height != 4006 {
		t.Fatal("watch changed the synchronized starting tip")
	}
	accepted := checkProcessReport(t, runQueryCLI(t, bin, append([]string{"verify-headers"}, append(slices.Clone(common), extension)...)...), 0, "ACCEPT")
	if accepted.Persistence != "saved" || accepted.Tip.Height != 4009 {
		t.Fatal("writer lock was not released for the next valid extension")
	}
}

type writerTickLog struct {
	once   sync.Once
	ticked chan struct{}
}

func (w *writerTickLog) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("tick: ACCEPT (caught up")) {
		w.once.Do(func() { close(w.ticked) })
	}
	return len(p), nil
}
