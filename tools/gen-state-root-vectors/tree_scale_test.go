//go:build candidate_tree_scale && candidate_retention && (darwin || linux)

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// Reuse the unmodified NodeTree/LevelDB retention driver with two larger,
// preselected finite inputs. Neither fixture authenticates a network history.
func TestTreeScaleChild(t *testing.T) {
	name := os.Getenv("TREE_SCALE_CASE")
	repetition, err := strconv.Atoi(os.Getenv("TREE_SCALE_REPETITION"))
	if err != nil || repetition < 0 || repetition >= 3 {
		t.Fatal("unselected scale repetition")
	}
	var item retentionInput
	switch name {
	case "scale-512-64-retain16":
		item = retentionInput{name, 512, 64, 16}
	case "scale-4096-64-retain16":
		item = retentionInput{name, 4096, 64, 16}
	default:
		t.Fatal("unselected scale workload")
	}
	dir := filepath.Join(t.TempDir(), name)
	retentionMust(os.Mkdir(dir, 0o700))
	retentionMust(os.WriteFile(filepath.Join(dir, ".owned"), []byte(nodeTree+"\n"+name+"\n"), 0o600))
	row := retentionChild(item, dir).(map[string]any)
	raw, err := json.Marshal(row["conformance"])
	retentionMust(err)
	var normalized any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	retentionMust(decoder.Decode(&normalized))
	raw, err = json.Marshal(normalized)
	retentionMust(err)
	digest := sha256.Sum256(raw)
	result := map[string]any{
		"conformance": normalized,
		"sample": map[string]any{
			"case": name, "repetition": repetition,
			"go_version":         runtime.Version(),
			"conformance_sha256": hex.EncodeToString(digest[:]),
			"measurement":        row["measurements"],
		},
	}
	raw, err = json.Marshal(result)
	retentionMust(err)
	fmt.Println("TREE_SCALE_RECORD=" + string(raw))
}
