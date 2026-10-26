//go:build candidate_source_manager_frontier

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/zenon-network/go-zenon/common/db"
)

func TestSourceManagerIteratorKeepsEmptyAndOmitsDelete(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stage       int
		empty, zero uint64
	}{
		{"deleted", 0, 0, 0}, {"present-empty", 1, 1, 0}, {"zero32", 2, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := db.NewMemDB()
			if err := db.SetFrontier(view, managerIdentifier(tc.stage), []byte("fixture")); err != nil {
				t.Fatal(err)
			}
			if err := view.Put(managerKey(), nil); err != nil {
				t.Fatal(err)
			}
			if tc.stage == 0 {
				if err := view.Delete(managerKey()); err != nil {
					t.Fatal(err)
				}
			} else if tc.stage == 2 {
				if err := view.Put(managerKey(), make([]byte, 32)); err != nil {
					t.Fatal(err)
				}
			}
			// Independent literal protobuf and put-wire expectations. In the
			// deleted case the original iterator still enumerates this key with
			// empty Value; a logical frontier must omit it using Get/Has semantics.
			hash := managerHashes[tc.stage]
			height := tc.stage + 1
			literal := "010100260a220a20" + hash + fmt.Sprintf("10%02x", height) +
				"012101" + hash + fmt.Sprintf("08%016x", height) +
				fmt.Sprintf("010902%016x0766697874757265", height)
			wantRecords := uint64(3)
			if tc.stage != 0 {
				literal += "0120" + hex.EncodeToString(managerKey())
				if tc.stage == 1 {
					literal += "00"
				} else {
					literal += "20" + strings.Repeat("00", 32)
				}
				wantRecords++
			}
			want, err := hex.DecodeString(literal)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(want)
			got, err := managerFrontier(view, tc.stage)
			if err != nil || got.Records != wantRecords || got.WireBytes != uint64(len(want)) ||
				got.SHA256 != hex.EncodeToString(digest[:]) || got.EmptyBalances != tc.empty || got.ZeroBalances != tc.zero ||
				got.TypedBalances != tc.empty+tc.zero {
				t.Fatalf("logical iterator differs from literal selected state: %+v %v", got, err)
			}
		})
	}
}

func TestSourceManagerHelpAndInvalidOptionsNeverComplete(t *testing.T) {
	private := "PRIVATE_CONTROL_ARGUMENT"
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"--help"}, 0}, {nil, 64}, {[]string{"--unknown", private}, 64},
		{[]string{"--step", "00", "--root", private}, 64},
	} {
		var output, diagnostic bytes.Buffer
		code := managerCapture(tc.args, &output, &diagnostic)
		var result map[string]any
		if code != tc.code || output.Len() != 0 || strings.Contains(diagnostic.String(), private) ||
			json.Unmarshal(diagnostic.Bytes(), &result) != nil || result["status"] != "UNKNOWN" ||
			result["phase"] != "options" || result["production_state_value_accepted"] != false {
			t.Fatal("help or invalid options became a completed producer or echoed an argument")
		}
	}
}
