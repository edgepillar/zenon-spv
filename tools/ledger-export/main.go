// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type diskStore struct {
	*leveldb.DB
	input *readOnlyStorage
}
type diskSnapshot struct{ *leveldb.Snapshot }

func (d diskStore) Snapshot() (rawSnapshot, error) {
	view, err := d.DB.GetSnapshot()
	if err != nil {
		return nil, err
	}
	return diskSnapshot{view}, nil
}
func (v diskSnapshot) Get(key []byte) ([]byte, error) {
	return v.Snapshot.Get(key, &opt.ReadOptions{DontFillCache: true})
}
func (v diskSnapshot) Iterator() rawIterator {
	return v.Snapshot.NewIterator(util.BytesPrefix([]byte{0x55}), &opt.ReadOptions{DontFillCache: true})
}

func openReadOnly(path string) (rawStore, error) {
	input := &readOnlyStorage{path: path}
	if _, err := input.List(storage.TypeAll); err != nil {
		return nil, refusal("input_open")
	}
	db, err := leveldb.Open(input, &opt.Options{ReadOnly: true, ErrorIfMissing: true,
		OpenFilesCacheCapacity: 16, BlockCacheCapacity: 4 << 20, Strict: opt.StrictAll})
	if err != nil {
		input.Close()
		return nil, refusal("input_open")
	}
	return diskStore{db, input}, nil
}

func (d diskStore) Close() error { return errors.Join(d.DB.Close(), d.input.Close()) }

type config struct {
	path     string
	selected selection
	caps     limits
}

func decimal(text string) (uint64, error) {
	if len(text) == 0 || len(text) > 20 || (len(text) > 1 && text[0] == '0') {
		return 0, refusal("options")
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return 0, refusal("options")
		}
	}
	n, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, refusal("options")
	}
	return n, nil
}

func options(args []string) (config, error) {
	var c config
	values := map[string]string{"layout": "", "immutable-copy": "", "expect-height": "", "expect-hash": "", "provenance-sha256": "",
		"max-bytes": "268435456", "max-records": "2000000", "max-scan-bytes": "268435456", "max-scan-records": "2000000", "max-key-bytes": "1024", "max-value-bytes": "1048576"}
	seen := map[string]bool{}
	bytes := 0
	if len(args) > 32 {
		return c, refusal("options")
	}
	for i := 0; i < len(args); i++ {
		bytes += len(args[i])
		if !strings.HasPrefix(args[i], "--") {
			return c, refusal("options")
		}
		name, value, inline := strings.Cut(args[i][2:], "=")
		if _, ok := values[name]; !ok || seen[name] {
			return c, refusal("options")
		}
		seen[name] = true
		if !inline {
			i++
			if i == len(args) {
				return c, refusal("options")
			}
			value = args[i]
			bytes += len(value)
		}
		if bytes > 16<<10 {
			return c, refusal("options")
		}
		values[name] = value
	}
	if values["layout"] != layout || values["immutable-copy"] == "" {
		return c, refusal("options")
	}
	c.path = values["immutable-copy"]
	c.selected.Hash, c.selected.Provenance = values["expect-hash"], values["provenance-sha256"]
	names := []string{"expect-height", "max-bytes", "max-records", "max-scan-bytes", "max-scan-records", "max-key-bytes", "max-value-bytes"}
	numbers := make([]uint64, len(names))
	for i, name := range names {
		n, err := decimal(values[name])
		if err != nil {
			return config{}, err
		}
		numbers[i] = n
	}
	c.selected.Height = numbers[0]
	c.caps = limits{numbers[1], numbers[2], numbers[3], numbers[4], numbers[5], numbers[6]}
	if !c.caps.valid() {
		return config{}, refusal("limits")
	}
	if _, err := c.selected.physicalIdentifier(); err != nil {
		return config{}, err
	}
	return c, nil
}

func ordinaryDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if filepath.Dir(current) == current {
			return true
		}
	}
}

func scope() map[string]any {
	return map[string]any{"input_role_required": "declared-immutable-copy", "input_immutability_authenticated": false, "ledger_origin_authenticated": false,
		"snapshot_completeness_authenticated": false, "representative_dataset_accepted": false,
		"profile_agreed": false, "network_activation_authenticated": false,
		"header_authentication_executed": false, "canonical_chain_qualified": false,
		"absence_or_delete_proof":        false,
		"state_value_acceptance_enabled": false}
}

const usage = "Export a declared immutable Zenon ledger frontier copy as ordered put records.\n" +
	"Required: --layout zenon-9c71-frontier-v1 --immutable-copy PATH --expect-height N --expect-hash HEX --provenance-sha256 HEX\n" +
	"Optional: --max-bytes N --max-records N --max-scan-bytes N --max-scan-records N --max-key-bytes N --max-value-bytes N\n" +
	"Binary stdout; one bounded JSON completion record on stderr. Input trust and completeness require separate acceptance.\n"

func run(ctx context.Context, args []string, stdout, stderr io.Writer, opener func(string) (rawStore, error)) (exit int) {
	report := map[string]any{"format": "zenon-frontier-export/v1", "status": "UNKNOWN", "put_stream_complete": false,
		"source_layout_node_revision": nodeRevision, "layout": layout, "scope": scope()}
	defer func() {
		if recover() != nil {
			report["status"], report["put_stream_complete"], report["reason"] = "UNKNOWN", false, "backend_failure"
			delete(report, "statistics")
			exit = 1
		}
		if err := json.NewEncoder(stderr).Encode(report); err != nil {
			exit = 1
		}
	}()
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		// Help is not an export receipt. The defer still emits UNKNOWN.
		if _, err := io.WriteString(stdout, usage); err != nil {
			return 1
		}
		report["reason"] = "help_only"
		return 0
	}
	c, err := options(args)
	if err == nil && ctx.Err() != nil {
		err = refusal("canceled")
	}
	if err == nil && !ordinaryDirectory(c.path) {
		err = refusal("input_directory")
	}
	var stats statistics
	if err == nil {
		var db rawStore
		db, err = opener(c.path)
		if err == nil && db == nil {
			err = refusal("input_open")
		}
		if err == nil {
			stats, err = exportStore(ctx, db, stdout, c.selected, c.caps)
		}
	}
	if err != nil {
		report["reason"] = reason(err)
		return 1
	}
	if ctx.Err() != nil {
		report["reason"] = "canceled"
		return 1
	}
	report["status"], report["put_stream_complete"], report["iterator_eof_observed"] = "SELECTED_FRONTIER_EXPORTED", true, true
	report["selection"], report["limits"], report["statistics"] = c.selected, c.caps, stats
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	done, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			// Closing a blocking inherited stdout can itself wait for an
			// outstanding write. A read-only producer may abort after its
			// grace period. Missing completion metadata plus exit 130 is
			// UNKNOWN; the outer controller must preserve the actual prefix.
			timer := time.AfterFunc(500*time.Millisecond, func() { os.Exit(130) })
			_ = os.Stdout.Close()
			<-done
			timer.Stop()
		case <-done:
		}
	}()
	exit := run(ctx, os.Args[1:], os.Stdout, os.Stderr, openReadOnly)
	close(done)
	<-joined
	stop()
	os.Exit(exit)
}
