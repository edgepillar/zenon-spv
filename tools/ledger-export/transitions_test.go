// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// Small physical fixtures complement the separately source-bound real Manager
// Add/Pop comparison. They do not execute that Manager or validate Momentums.
func compiledFrontierTransitions(t *testing.T, binary string) {
	t.Helper()
	key := unhex(t, "03"+strings.Repeat("ee", 20)+"03"+strings.Repeat("dd", 10))
	physicalKey := append([]byte{0x55}, key...)
	path := createDisk(t, []pair{{[]byte{0x55, 0}, metadata(t)}, {physicalKey, nil}})
	type state struct {
		hash, height, suffix, encodedValue string
		present, empty                     bool
	}
	states := []state{
		{selected().Hash, "3000", "b817", "", false, false},
		{strings.Repeat("33", 32), "3001", "b917", "00", true, true},
		{strings.Repeat("44", 32), "3002", "ba17", strings.Repeat("00", 33), true, false},
		{strings.Repeat("55", 32), "3003", "bb17", "", false, false},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for step, index := range []int{0, 1, 2, 3, 2, 1, 0} {
		s := states[index]
		t.Run(strconv.Itoa(step), func(t *testing.T) {
			// This writer models only independently selected physical rows. Stop it
			// before launching the ordinary exporter; never read a writable live DB.
			disk, err := leveldb.OpenFile(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			meta := unhex(t, "000a220a20"+s.hash+"10"+s.suffix)
			var batch leveldb.Batch
			batch.Put([]byte{0x55, 0}, meta)
			batch.Put(physicalKey, unhex(t, s.encodedValue))
			if err = disk.Write(&batch, nil); err != nil {
				_ = disk.Close()
				t.Fatal(err)
			}
			if err = disk.Close(); err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(image(t, path))
			args := arguments(path)
			args[5], args[7] = s.height, s.hash
			var out, diagnostic bytes.Buffer
			cmd := exec.CommandContext(ctx, binary, args...)
			cmd.Stdout, cmd.Stderr = &out, &diagnostic
			if err = cmd.Run(); err != nil {
				t.Fatalf("transition export: %v %s", err, diagnostic.Bytes())
			}
			report := receipt(t, diagnostic.Bytes())
			expected := unhex(t, "01010027"+hex.EncodeToString(meta[1:]))
			if s.present {
				value := "00"
				if !s.empty {
					value = "20" + strings.Repeat("00", 32)
				}
				expected = append(expected, unhex(t, "0120"+hex.EncodeToString(key)+value)...)
			}
			wantRecords, wantEmpty, wantTombstones := float64(1), float64(0), float64(1)
			if s.present {
				wantRecords, wantTombstones = 2, 0
			}
			if s.empty {
				wantEmpty = 1
			}
			stats := report["statistics"].(map[string]any)
			digest := sha256.Sum256(expected)
			if report["status"] != "SELECTED_FRONTIER_EXPORTED" || report["put_stream_complete"] != true ||
				!bytes.Equal(out.Bytes(), expected) || stats["records"] != wantRecords || stats["present_empty_values"] != wantEmpty ||
				stats["physical_tombstones_omitted"] != wantTombstones || stats["put_stream_sha256"] != hex.EncodeToString(digest[:]) {
				t.Fatal("selected transition changed literal bytes, empty/tombstone semantics or counts")
			}
			// A height match cannot replace the selected full identifier.
			args[7] = strings.Repeat("66", 32)
			out.Reset()
			diagnostic.Reset()
			rejected := exec.CommandContext(ctx, binary, args...)
			rejected.Stdout, rejected.Stderr = &out, &diagnostic
			if rejected.Run() == nil || rejected.ProcessState == nil || rejected.ProcessState.ExitCode() != 1 ||
				out.Len() != 0 || receipt(t, diagnostic.Bytes())["status"] != "UNKNOWN" {
				t.Fatal("same-height foreign identifier was not refused before export")
			}
			after, _ := json.Marshal(image(t, path))
			if !bytes.Equal(before, after) {
				t.Fatal("ordinary processes changed the closed fixture")
			}
		})
	}
	t.Log("ordinary_transition_processes=14 completed_snapshots=7 same_height_refusals=7 source_node_manager_executions=0 acceptance_enabled=false")
}
