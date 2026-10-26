//go:build candidate_core_init_failure

// SPDX-License-Identifier: GPL-3.0-only
package zenon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/zenon-network/go-zenon/chain"
)

type candidateInitFailureCall struct {
	Error string `json:"error"`
	Panic bool   `json:"panic"`
}

type candidateInitFailureHandles struct {
	LedgerOpen bool   `json:"ledger_open"`
	CacheOpen  bool   `json:"cache_open"`
	Consensus  string `json:"consensus"`
	TreeReady  bool   `json:"tree_ready"`
}

type candidateInitFailureMarker struct {
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256"`
	SameFile     bool   `json:"same_file"`
	BytesMatched bool   `json:"bytes_matched"`
}

type candidateInitFailureTeardown struct {
	Manager string                   `json:"manager"`
	Call    candidateInitFailureCall `json:"call"`
}

type candidateInitFailureObservation struct {
	Case             string                              `json:"case"`
	FaultSetup       candidateInitFailureCall            `json:"fault_setup"`
	BeforeInit       candidateInitFailureHandles         `json:"before_Init"`
	Init             candidateInitFailureCall            `json:"Init"`
	AfterInit        candidateInitFailureHandles         `json:"after_Init"`
	Stop             candidateInitFailureCall            `json:"Stop"`
	AfterStop        candidateInitFailureHandles         `json:"after_Stop"`
	StoreReopen      map[string]candidateInitFailureCall `json:"store_reopen"`
	SecondStop       candidateInitFailureCall            `json:"second_Stop"`
	Marker           *candidateInitFailureMarker         `json:"marker,omitempty"`
	ExplicitTeardown []candidateInitFailureTeardown      `json:"explicit_teardown,omitempty"`
}

func candidateInitFailureClass(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, leveldb.ErrClosed) {
		return "leveldb-closed"
	}
	if errors.Is(err, syscall.ENOTDIR) {
		return "not-directory"
	}
	if err.Error() == "can't initialize chain: ledger-unavailable" {
		return "ledger-unavailable"
	}
	if errors.Is(err, ErrStopIncomplete) {
		return "stop-incomplete"
	}
	return "other-error"
}

func candidateInitFailureInvoke(fn func() error) (out candidateInitFailureCall) {
	out.Error = "none"
	defer func() {
		if recover() != nil {
			out.Panic = true
		}
	}()
	out.Error = candidateInitFailureClass(fn())
	return out
}

func candidateInitFailureHandleState(z *zenon) (candidateInitFailureHandles, error) {
	ledgerOpen, cacheOpen, err := chain.CandidateCoreInitFailureHandles(z.chain)
	if err != nil {
		return candidateInitFailureHandles{}, err
	}
	// The selected consensus handle was opened by NewZenon. This is an actual
	// read on that same handle, independent of subsequent fresh-path probes.
	_, readErr := z.levelDb.Has([]byte("candidate-init-failure-read-only-check"), nil)
	return candidateInitFailureHandles{
		LedgerOpen: ledgerOpen, CacheOpen: cacheOpen,
		Consensus: candidateInitFailureClass(readErr), TreeReady: z.chain.StateTreeReady(),
	}, nil
}

func candidateInitFailurePrivateRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) {
		return errors.New("new physical private root required")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(root) {
		return errors.New("physical private root required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("private root mode required")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		return errors.New("new empty private root required")
	}
	return nil
}

func candidateInitFailureReopen(root, name string) error {
	// ErrorIfMissing prevents a successful probe from inventing a new empty
	// database at an incorrect path. All three selected stores predate Init.
	db, err := leveldb.OpenFile(filepath.Join(root, name), &opt.Options{ErrorIfMissing: true})
	if err != nil {
		return err
	}
	return db.Close()
}

// CandidateCoreInitFailureCapture observes failed Init followed by Stop using
// one fresh keyless core. It selects no additional runtime patch, Start or network work.
// Its observations are not a success decision; the outer controller must check
// the actual exit, complete capture, source identity and expected case values.
func CandidateCoreInitFailureCapture(cfg *Config, mode string) (out candidateInitFailureObservation, err error) {
	if cfg == nil || cfg.GenesisConfig == nil || cfg.ProducingKeyPair != nil ||
		(mode != "ledger-closed-before-Init" && mode != "state-tree-path-file") {
		return out, errors.New("selected keyless Init failure case required")
	}
	if err := candidateInitFailurePrivateRoot(cfg.DataDir); err != nil {
		return out, err
	}
	out.Case = mode
	markerBytes := []byte("owned Init open-error control\n")
	markerPath := filepath.Clean(cfg.StateTreeDir())
	var markerInfo os.FileInfo
	if mode == "state-tree-path-file" {
		if filepath.Dir(markerPath) != filepath.Clean(cfg.DataDir) {
			return out, errors.New("selected direct-child state-tree path required")
		}
		file, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return out, errors.New("owned fault marker creation failed")
		}
		n, writeErr := file.Write(markerBytes)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil || n != len(markerBytes) {
			return out, errors.New("owned fault marker incomplete")
		}
		markerInfo, err = os.Lstat(markerPath)
		if err != nil || !markerInfo.Mode().IsRegular() {
			return out, errors.New("owned regular marker required")
		}
		digest := sha256.Sum256(markerBytes)
		out.Marker = &candidateInitFailureMarker{BeforeSHA256: hex.EncodeToString(digest[:])}
	}
	value, err := NewZenon(cfg)
	if err != nil {
		return out, errors.New("real keyless core construction failed")
	}
	z, ok := value.(*zenon)
	if !ok || z.Producer().GetCoinBase() != nil || z.Config().ProducingKeyPair != nil {
		return out, errors.New("real keyless core invariant failed")
	}
	out.FaultSetup = candidateInitFailureCall{Error: "none"}
	if mode == "ledger-closed-before-Init" {
		out.FaultSetup = candidateInitFailureInvoke(func() error {
			return chain.CandidateCoreInitFailureCloseLedger(z.chain)
		})
	}
	out.BeforeInit, err = candidateInitFailureHandleState(z)
	if err != nil {
		return out, err
	}
	out.Init = candidateInitFailureInvoke(z.Init)
	out.AfterInit, err = candidateInitFailureHandleState(z)
	if err != nil {
		return out, err
	}
	out.Stop = candidateInitFailureInvoke(z.Stop)
	out.AfterStop, err = candidateInitFailureHandleState(z)
	if err != nil {
		return out, err
	}
	out.StoreReopen = make(map[string]candidateInitFailureCall)
	for _, name := range []string{"nom", "cache", "consensus"} {
		selected := name
		out.StoreReopen[name] = candidateInitFailureInvoke(func() error {
			return candidateInitFailureReopen(cfg.DataDir, selected)
		})
	}
	// A terminal failed Stop is never retried as successful cleanup. Retain its
	// result, then attempt each remaining manager independently for diagnosis.
	if out.Stop.Panic || out.Stop.Error != "none" {
		for _, item := range []struct {
			name string
			stop func() error
		}{
			{"pillar", z.pillar.Stop}, {"subscribe", z.subscribe.Stop},
			{"printer", z.evPrinter.Stop}, {"consensus", z.consensus.Stop},
			{"chain", z.chain.Stop}, {"consensus-db", z.levelDb.Close},
		} {
			out.ExplicitTeardown = append(out.ExplicitTeardown,
				candidateInitFailureTeardown{item.name, candidateInitFailureInvoke(item.stop)})
		}
	} else {
		out.SecondStop = candidateInitFailureInvoke(z.Stop)
	}
	if out.Marker != nil {
		info, statErr := os.Lstat(markerPath)
		if statErr != nil || !info.Mode().IsRegular() || info.Size() != int64(len(markerBytes)) {
			return out, errors.New("owned fault marker changed")
		}
		file, openErr := os.Open(markerPath)
		if openErr != nil {
			return out, errors.New("owned marker read failed")
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, int64(len(markerBytes)+1)))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return out, errors.New("owned marker read incomplete")
		}
		digest := sha256.Sum256(raw)
		out.Marker.AfterSHA256 = hex.EncodeToString(digest[:])
		out.Marker.SameFile = os.SameFile(markerInfo, info)
		out.Marker.BytesMatched = bytes.Equal(raw, markerBytes)
	}
	return out, nil
}
