package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// stateFileVersion identifies legacy state without an activation profile.
// profileStateFileVersion prevents older clients from ignoring a saved
// profile. Bump on any breaking change; an unknown version on
// load returns an error rather than best-effort parsing (mirrors
// the refusal-semantics discipline of ADR 0001).
const (
	stateFileVersion        uint32 = 1
	profileStateFileVersion uint32 = 2
)

// persistedState is the on-disk shape of HeaderState. Only the
// fields the verifier needs to resume are persisted; the Policy in
// effect at load time governs Capacity (the loaded slice is
// truncated to the current Capacity if W has shrunk).
type persistedState struct {
	ProtocolProfile *ProtocolProfile `json:"protocol_profile,omitempty"`
	Version         uint32           `json:"version"`
	Genesis         GenesisTrustRoot `json:"genesis"`
	Window          []chain.Header   `json:"retained_window"`
	Capacity        int              `json:"capacity"`
}

// SaveHeaderState writes state to path as JSON. The sequence is:
// write to a temporary file in the same directory, fsync(tmp),
// close, rename, then fsync the parent directory on non-Windows
// platforms. The caller must ensure exclusive ownership of path.
//
// On filesystems supporting atomic rename and directory sync, both
// syncs matter: fsync(tmp) flushes the contents, while fsync(parent)
// flushes the replacement directory entry. Neither error is ignored.
// Windows retains the existing best-effort replacement behavior;
// parent-directory sync is skipped and the same crash-durability
// guarantee is not claimed there.
//
// An error after rename does not undo the replacement: the new state
// may already be visible, but its crash durability is unconfirmed.
//
// Only call after a successful VerifyHeaders ACCEPT — persisting a
// state that wasn't proven would silently lower the SPV's trust.
func SaveHeaderState(path string, state HeaderState) error {
	return saveHeaderState(path, state, os.Open)
}

// openDir is injected to exercise failures after the atomic rename.
func saveHeaderState(path string, state HeaderState, openDir func(string) (*os.File, error)) error {
	if path == "" {
		return errors.New("verify: SaveHeaderState: empty path")
	}
	if err := state.ValidateHeaderVersions(); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".spv-state-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	body := persistedState{
		Version:         stateFileVersion,
		ProtocolProfile: cloneProtocolProfile(state.ProtocolProfile),
		Genesis:         state.Genesis,
		Window:          state.RetainedWindow,
		Capacity:        state.Capacity,
	}
	if body.ProtocolProfile != nil {
		body.Version = profileStateFileVersion
	}
	if err := enc.Encode(body); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("encode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := openDir(dir)
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("sync parent directory: %w", err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("close parent directory: %w", err)
	}
	return nil
}

// LoadHeaderState reads a persisted state file. Returns an error if
// the file does not exist (callers wanting "load if present" should
// use LoadOrInit). Refuses unknown wire versions per ADR 0001's
// versioning policy and unsupported momentum versions throughout
// the stored window, before any policy-driven truncation.
func LoadHeaderState(path string) (HeaderState, error) {
	f, err := os.Open(path)
	if err != nil {
		return HeaderState{}, err
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(f)
	if err != nil {
		return HeaderState{}, fmt.Errorf("read: %w", err)
	}
	var body persistedState
	if err := json.Unmarshal(raw, &body); err != nil {
		return HeaderState{}, fmt.Errorf("parse: %w", err)
	}
	if body.Version != stateFileVersion && body.Version != profileStateFileVersion {
		return HeaderState{}, fmt.Errorf("unsupported state-file version %d (supported 1 and 2)", body.Version)
	}
	if (body.Version == profileStateFileVersion) != (body.ProtocolProfile != nil) {
		return HeaderState{}, errors.New("state file schema/profile mismatch")
	}
	if body.Genesis.HeaderHash.IsZero() {
		return HeaderState{}, errors.New("state file: genesis HeaderHash is zero — likely corrupted")
	}
	state := HeaderState{
		ProtocolProfile: cloneProtocolProfile(body.ProtocolProfile),
		Genesis:         body.Genesis,
		RetainedWindow:  body.Window,
		Capacity:        body.Capacity,
	}
	if err := state.ValidateHeaderVersions(); err != nil {
		return HeaderState{}, fmt.Errorf("load state: %w", err)
	}
	return state, nil
}

// LoadOrInit returns the persisted state at path if it exists and
// matches the supplied genesis trust root, or a fresh state anchored
// at genesis if the file does not exist.
//
// A genesis-trust-root mismatch on the loaded file is fatal — it's
// either a corrupted file, a deliberate trust-root change (which
// requires a new state file by policy), or an attempt to point a
// mainnet verifier at testnet state.
//
// If policy.W has shrunk since the file was written, the loaded
// retained window is truncated to keep the most recent
// capacityForPolicy(policy) == policy.W + 1 headers (the spec
// §2.3 capacity that keeps the target plus W headers past it),
// and Capacity is updated to match the new policy.
func LoadOrInit(path string, genesis GenesisTrustRoot, policy Policy) (HeaderState, error) {
	if err := validateProfileAnchor(policy.ProtocolProfile, genesis); err != nil {
		return HeaderState{}, err
	}
	loaded, err := LoadHeaderState(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewHeaderState(genesis, policy), nil
	}
	if err != nil {
		return HeaderState{}, err
	}
	if !sameProtocolProfile(loaded.ProtocolProfile, policy.ProtocolProfile) {
		return HeaderState{}, ErrProtocolProfileMismatch
	}
	if loaded.Genesis.Height != genesis.Height {
		return HeaderState{}, errors.New("state file anchor height differs from configured anchor")
	}
	if loaded.Genesis.ChainID != genesis.ChainID {
		return HeaderState{}, fmt.Errorf("state file chain_id=%d != configured chain_id=%d (refuse to mix networks)",
			loaded.Genesis.ChainID, genesis.ChainID)
	}
	if loaded.Genesis.HeaderHash != genesis.HeaderHash {
		return HeaderState{}, fmt.Errorf("state file genesis hash %x != configured genesis hash %x (different trust roots)",
			loaded.Genesis.HeaderHash, genesis.HeaderHash)
	}
	cap := capacityForPolicy(policy)
	loaded.Capacity = cap
	if len(loaded.RetainedWindow) > cap {
		loaded.RetainedWindow = loaded.RetainedWindow[len(loaded.RetainedWindow)-cap:]
	}
	return loaded, nil
}
