package proof

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

// ErrBundleTooLarge is returned by bounded file loaders when the
// file's size exceeds the supplied maxBytes cap. CLI surfaces
// translate this into REFUSED / ReasonOversizedBundle with exit
// code 2 — a too-big bundle is not a proof of badness, just a
// guardrail breach the verifier refuses to evaluate.
var ErrBundleTooLarge = errors.New("bundle exceeds size cap")

// LoadHeaderBundle reads and validates a JSON HeaderBundle from disk.
// Per ADR 0001, an unknown wire version MUST be refused, not
// best-effort parsed.
//
// Deprecated for production paths: use LoadHeaderBundleWithLimits with
// policy-derived byte and count caps so oversized arrays stop decoding
// before the verifier's preflight. Kept available for tests and tooling
// that already validate input size themselves.
func LoadHeaderBundle(path string) (HeaderBundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return HeaderBundle{}, fmt.Errorf("read bundle: %w", err)
	}
	return UnmarshalHeaderBundleJSON(b)
}

// LoadHeaderBundleBounded reads and validates a JSON HeaderBundle
// from disk, refusing if the file exceeds maxBytes. The check uses
// io.LimitReader(file, maxBytes+1) so the underlying file is never
// fully read past the cap — a 10 GB hostile bundle is rejected
// after maxBytes+1 bytes, not after the full 10 GB.
//
// maxBytes <= 0 disables the cap (back-compat for tests that
// don't care about the wire size).
func LoadHeaderBundleBounded(path string, maxBytes int64) (HeaderBundle, error) {
	return LoadHeaderBundleWithLimits(path, maxBytes, DecodeLimits{})
}

// LoadHeaderBundleWithLimits applies byte, array-count, and aggregate row-count
// caps before the verifier receives a bundle. Counts stop before decoding an
// excess row. Zero counts and nonpositive maxBytes retain the legacy opt-out;
// production callers should supply positive policy-derived limits.
func LoadHeaderBundleWithLimits(path string, maxBytes int64, limits DecodeLimits) (HeaderBundle, error) {
	if err := limits.validate(); err != nil {
		return HeaderBundle{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return HeaderBundle{}, fmt.Errorf("open bundle: %w", err)
	}
	// Discard the Close error explicitly: read-only file, error is
	// non-actionable and would only mask a more useful error from
	// the read path above.
	defer func() { _ = f.Close() }()

	var src io.Reader = f
	if maxBytes > 0 {
		// Read one overflow-probe byte, saturating at MaxInt64 instead
		// of wrapping the reader limit into a negative number.
		readLimit := maxBytes
		if readLimit < math.MaxInt64 {
			readLimit++
		}
		src = io.LimitReader(f, readLimit)
	}
	b, err := io.ReadAll(src)
	if err != nil {
		return HeaderBundle{}, fmt.Errorf("read bundle: %w", err)
	}
	if maxBytes > 0 && int64(len(b)) > maxBytes {
		return HeaderBundle{}, fmt.Errorf("%w: max=%d bytes, file is at least %d bytes",
			ErrBundleTooLarge, maxBytes, len(b))
	}
	return unmarshalHeaderBundleJSON(b, limits)
}

// UnmarshalHeaderBundleJSON parses a JSON-encoded HeaderBundle and checks its
// wire version. The type's decoder refuses repeated known top-level fields,
// including case and escaped aliases, before they can overwrite evidence.
func UnmarshalHeaderBundleJSON(data []byte) (HeaderBundle, error) {
	return unmarshalHeaderBundleJSON(data, DecodeLimits{})
}

func unmarshalHeaderBundleJSON(data []byte, limits DecodeLimits) (HeaderBundle, error) {
	var hb HeaderBundle
	// Preserve whole-document syntax and nesting checks before streaming fields.
	if err := json.Unmarshal(data, &bundleJSONDecoder{target: &hb, limits: limits}); err != nil {
		return HeaderBundle{}, fmt.Errorf("parse bundle: %w", err)
	}
	if hb.Version != WireVersion {
		return HeaderBundle{}, fmt.Errorf("unsupported wire version %d (expected %d)", hb.Version, WireVersion)
	}
	return hb, nil
}

type bundleJSONDecoder struct {
	target *HeaderBundle
	limits DecodeLimits
}

func (decoder *bundleJSONDecoder) UnmarshalJSON(raw []byte) error {
	return decoder.target.unmarshalJSON(raw, decoder.limits)
}

// MarshalHeaderBundleJSON writes hb to indented JSON for fixtures.
func MarshalHeaderBundleJSON(hb HeaderBundle) ([]byte, error) {
	return json.MarshalIndent(hb, "", "  ")
}
