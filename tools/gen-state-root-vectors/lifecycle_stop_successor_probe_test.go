//go:build candidate_state_tree_stop_successor

// SPDX-License-Identifier: GPL-3.0-only
// Controlled component lifecycle schedules; no Chain.Start or live service.
package chain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/zenon-network/go-zenon/chain/momentum"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

type lifecycleControl struct {
	target                   *stateTree
	mu                       sync.Mutex
	counts                   map[string]int
	entry, snapshot, worker  chan struct{}
	snapshots, workers       chan struct{}
	exits                    []<-chan struct{}
	snapshotOnce, workerOnce sync.Once
}

var lifecycleSelected *lifecycleControl

// The preparer injects exactly three calls, separately pinned from the proposal.
func lifecycleCheckpoint(name string, tree *stateTree, exit <-chan struct{}) {
	c := lifecycleSelected
	if c == nil || c.target != tree {
		return
	}
	c.mu.Lock()
	c.counts[name]++
	if name == "worker-claimed" {
		c.exits = append(c.exits, exit)
	}
	c.mu.Unlock()
	switch name {
	case "launch-entry":
		c.entry <- struct{}{}
	case "launch-snapshot":
		c.snapshot <- struct{}{}
		if c.snapshots != nil {
			<-c.snapshots
		}
	case "worker-claimed":
		c.worker <- struct{}{}
		if c.workers != nil {
			<-c.workers
		}
	default:
		panic("unselected scheduler checkpoint")
	}
}
func (c *lifecycleControl) release() {
	if c.snapshots != nil {
		c.snapshotOnce.Do(func() { close(c.snapshots) })
	}
	if c.workers != nil {
		c.workerOnce.Do(func() { close(c.workers) })
	}
}
func (c *lifecycleControl) count() any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{"launch_entry": c.counts["launch-entry"], "launch_snapshot": c.counts["launch-snapshot"], "worker_claimed": c.counts["worker-claimed"]}
}
func (c *lifecycleControl) exitChannels() []<-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]<-chan struct{}{}, c.exits...)
}
func lifecycleWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("controlled lifecycle schedule did not complete")
	}
}
func lifecycleResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("controlled lifecycle operation did not return")
		return nil
	}
}
func lifecycleError(err error) any {
	if err != nil && err.Error() == "state tree: stopped" {
		return "stopped"
	}
	return recoveryError(err)
}
func lifecycleClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

type lifecycleManager struct {
	*recoveryManager
	entered, release chan struct{}
	once             sync.Once
}

func (m *lifecycleManager) Frontier() db.DB {
	if m.entered != nil {
		m.once.Do(func() { close(m.entered); <-m.release })
	}
	return m.recoveryManager.Frontier()
}

type lifecyclePatch struct {
	db.Patch
	entered, release chan struct{}
	dump, replay     int
	once             sync.Once
}

func (p *lifecyclePatch) Dump() []byte {
	p.dump++
	p.once.Do(func() { close(p.entered); <-p.release })
	return p.Patch.Dump()
}
func (p *lifecyclePatch) Replay(out db.PatchReplayer) error {
	p.replay++
	return p.Patch.Replay(out)
}
func lifecycleReads(s *stateTree, compute bool) []any {
	id := recoveryIdentifier("A", 2)
	root, err := s.StateRoot(id)
	value, proof, proofErr := s.GetProof(id, recoveryKey(false))
	rows := []any{
		map[string]any{"method": "StateRoot", "identifier": recoveryID(id), "root": root.String(), "value": nil, "proof": nil, "error": lifecycleError(err), "patch_callbacks": map[string]any{"dump": 0, "replay": 0}},
		map[string]any{"method": "GetProof", "identifier": recoveryID(id), "root": nil, "value": recoveryBytes(value), "proof": recoveryBytes(proof), "error": lifecycleError(proofErr), "patch_callbacks": map[string]any{"dump": 0, "replay": 0}},
	}
	if compute {
		p := &recoveryCounter{Patch: recoveryPatch("A", 99)}
		r, e := s.ComputeStateRoot(id, p)
		rows = append(rows, map[string]any{"method": "ComputeStateRoot", "identifier": recoveryID(id), "root": r.String(), "value": nil, "proof": nil, "error": lifecycleError(e), "patch_callbacks": map[string]any{"dump": p.dump, "replay": p.replay}})
	}
	return rows
}

func lifecycleCase(t *testing.T, variant, name string) any {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tree")
	st := newStateTree(dir, false)
	control := &lifecycleControl{target: st, counts: map[string]int{}, entry: make(chan struct{}, 8), snapshot: make(chan struct{}, 8), worker: make(chan struct{}, 8)}
	lifecycleSelected = control
	closed := false
	defer func() {
		control.release()
		for _, exit := range control.exitChannels() {
			lifecycleWait(t, exit)
		}
		if st.ldb != nil && !closed {
			_ = st.ldb.Close()
		}
		lifecycleSelected = nil
	}()
	m := &lifecycleManager{recoveryManager: &recoveryManager{}}
	cache := &recoveryCache{}
	recoverySelect(m.recoveryManager, cache, "A", 2)
	store := momentum.NewStore(&recoveryGenesis{}, m.data.Snapshot())
	phases := []any{}
	rows := func() []any {
		if st.ldb != nil && !closed {
			return recoveryRecords(st.ldb)
		}
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			return []any{}
		}
		return recoveryDiskRecords(dir)
	}
	phase := func(label string, compute bool) {
		reads := lifecycleReads(st, compute)
		var frontier any
		if st.tree != nil {
			frontier = recoveryID(st.tree.FrontierIdentifier())
		}
		st.rootCacheMu.Lock()
		cached := st.rootCache != nil
		st.rootCacheMu.Unlock()
		phases = append(phases, map[string]any{"name": label, "ready": st.StateTreeReady(), "quit_closed": lifecycleClosed(st.quit), "handle_assigned": st.ldb != nil, "retained_frontier": frontier, "root_cache_present": cached, "records": rows(), "reads": reads})
	}
	inits, stops := []any{}, []any{}
	var inflight, admission any
	startCalls := 0
	if name == "stop-before-init" {
		stops = append(stops, lifecycleError(st.stop()))
		st.startBuild(nil)
		startCalls++
		if st.buildExited != nil {
			lifecycleWait(t, st.buildExited)
		}
		phase("stopped-empty", false)
		err := st.Init(m, store)
		inits = append(inits, lifecycleError(err))
		phase("init-after-stop", false)
		stops = append(stops, lifecycleError(st.stop()))
		phase("after-final-stop", true)
	} else if name == "pending-init-stop" {
		m.entered, m.release = make(chan struct{}), make(chan struct{})
		defer func() {
			select {
			case <-m.release:
			default:
				close(m.release)
			}
		}()
		initDone := make(chan error, 1)
		go func() { initDone <- st.Init(m, store) }()
		lifecycleWait(t, m.entered)
		stopDone := make(chan error, 1)
		go func() { stopDone <- st.stop() }()
		lifecycleWait(t, st.quit)
		phase("stop-intent", false)
		close(m.release)
		inits = append(inits, lifecycleError(lifecycleResult(t, initDone)))
		stops = append(stops, lifecycleError(lifecycleResult(t, stopDone)))
		closed = true
		phase("after-stop", true)
	} else {
		err := st.Init(m, store)
		recoveryMust(err)
		inits = append(inits, nil)
		phase("initialized", false)
		switch name {
		case "init-before-stop":
			stops = append(stops, lifecycleError(st.stop()))
			closed = true
			phase("after-stop", true)
			inits = append(inits, lifecycleError(st.Init(m, store)))
			phase("reinit-after-stop", true)
		case "pending-stop-lock":
			st.changes.Lock()
			locked := true
			defer func() {
				if locked {
					st.changes.Unlock()
				}
			}()
			stopDone := make(chan error, 1)
			go func() { stopDone <- st.stop() }()
			lifecycleWait(t, st.quit)
			phase("stop-intent", false)
			st.changes.Unlock()
			locked = false
			stops = append(stops, lifecycleError(lifecycleResult(t, stopDone)))
			closed = true
			phase("after-stop", true)
		case "pending-compute-stop":
			p := &lifecyclePatch{Patch: recoveryPatch("A", 99), entered: make(chan struct{}), release: make(chan struct{})}
			defer func() {
				select {
				case <-p.release:
				default:
					close(p.release)
				}
			}()
			computeDone := make(chan struct{})
			var result types.Hash
			var computeErr error
			go func() { result, computeErr = st.ComputeStateRoot(recoveryIdentifier("A", 2), p); close(computeDone) }()
			lifecycleWait(t, p.entered)
			stopDone := make(chan error, 1)
			go func() { stopDone <- st.stop() }()
			lifecycleWait(t, st.quit)
			phase("stop-intent", false)
			close(p.release)
			lifecycleWait(t, computeDone)
			inflight = map[string]any{"root": result.String(), "error": lifecycleError(computeErr), "patch_callbacks": map[string]any{"dump": p.dump, "replay": p.replay}}
			stops = append(stops, lifecycleError(lifecycleResult(t, stopDone)))
			closed = true
			phase("after-stop", true)
		case "held-launches-stop":
			control.snapshots, control.workers = make(chan struct{}), make(chan struct{})
			launches := make(chan struct{}, 2)
			go func() { st.startBuild(nil); launches <- struct{}{} }()
			startCalls++
			lifecycleWait(t, control.snapshot)
			go func() { st.startBuild(nil); launches <- struct{}{} }()
			startCalls++
			if variant == "hash-bound" {
				lifecycleWait(t, control.snapshot)
			} else {
				lifecycleWait(t, control.entry)
				lifecycleWait(t, control.entry)
			}
			stopDone := make(chan error, 1)
			go func() { stopDone <- st.stop() }()
			lifecycleWait(t, st.quit)
			stopReturned := false
			var stopErr error
			if variant == "hash-bound" {
				stopErr = lifecycleResult(t, stopDone)
				closed = true
				stopReturned = true
			} else {
				select {
				case <-stopDone:
					t.Fatal("stop returned while the selected launch mutex was held")
				default:
				}
			}
			phase("stop-intent", false)
			control.snapshotOnce.Do(func() { close(control.snapshots) })
			lifecycleWait(t, launches)
			lifecycleWait(t, launches)
			if variant == "hash-bound" {
				lifecycleWait(t, control.worker)
				lifecycleWait(t, control.worker)
			} else {
				stopErr = lifecycleResult(t, stopDone)
				closed = true
			}
			admission = map[string]any{"stop_returned_while_snapshots_held": stopReturned, "published_after_stop_returned": stopReturned && st.buildExited != nil, "workers_awaited_by_harness": len(control.exitChannels())}
			control.workerOnce.Do(func() { close(control.workers) })
			for _, exit := range control.exitChannels() {
				lifecycleWait(t, exit)
			}
			stops = append(stops, lifecycleError(stopErr))
			phase("after-stop", true)
		default:
			panic("unselected lifecycle case")
		}
	}
	// Check whether Stop actually closed an assigned backend. The historical
	// stop-before-init case requires explicit harness cleanup of its reopened DB.
	var backend any
	extraClose := false
	if st.ldb != nil {
		r, e := st.tree.Root(recoveryIdentifier("A", 2))
		backend = map[string]any{"root": r.String(), "error": lifecycleError(e)}
		if e == nil {
			recoveryMust(st.ldb.Close())
			closed = true
			extraClose = true
		}
	}
	final := rows()
	result := map[string]any{"name": name, "init_errors": inits, "stop_errors": stops, "start_calls": startCalls, "phases": phases, "inflight_compute": inflight, "launch_admission": admission, "checkpoints": control.count(), "backend_after_final_stop": backend, "harness_extra_close_required": extraClose, "records_after_close_reopen": final, "manager_trace": m.trace, "consumer_result": "REFUSED"}
	return result
}

func TestCandidateStateTreeStop(t *testing.T) {
	variant := os.Getenv("ZENON_STOP_SUCCESSOR_VARIANT")
	if variant != "hash-bound" && variant != "monotonic-stop" {
		t.Fatal("select explicit lifecycle source variant")
	}
	handler := common.ChainLogger.GetHandler()
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	defer common.ChainLogger.SetHandler(handler)
	cases := []any{}
	for _, name := range []string{"stop-before-init", "init-before-stop", "pending-stop-lock", "pending-init-stop", "pending-compute-stop", "held-launches-stop"} {
		cases = append(cases, lifecycleCase(t, variant, name))
	}
	document := map[string]any{"format_version": 1, "kind": "successor-node-stop-lifecycle-observations", "variant": variant, "cases": cases, "node_revision": "9c71ae82fc983e16f914ae085d4034030c8ebe3b", "consumer_result": "REFUSED", "production_state_value_accepted": false, "background_build_batches_executed": false}
	raw, err := json.Marshal(document)
	recoveryMust(err)
	fmt.Printf("STATE_TREE_STOP=%s\n", raw)
}
