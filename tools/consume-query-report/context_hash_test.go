package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

type contextFingerprintVector struct {
	Name         string   `json:"name"`
	Context      settings `json:"context"`
	EncodedInput string   `json:"encoded_input_hex"`
	Expected     string   `json:"expected_fingerprint"`
}

func contextFingerprintVectors(t testing.TB) []contextFingerprintVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/context-fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []contextFingerprintVector
	if json.Unmarshal(raw, &vectors) != nil || len(vectors) != 6 {
		t.Fatal("selected context vectors are incomplete")
	}
	for _, vector := range vectors {
		encoded, err := hex.DecodeString(vector.EncodedInput)
		digest := sha3.Sum256(encoded)
		if err != nil || hex.EncodeToString(digest[:]) != vector.Expected || vector.Context.Fingerprint != vector.Expected {
			t.Fatal("complete independent encoded input does not bind the selected fingerprint")
		}
	}
	return vectors
}

func TestConsumerContextFingerprintVectors(t *testing.T) {
	for _, vector := range contextFingerprintVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			t.Run("preselected", func(t *testing.T) {
				var decoded settings
				if !decodeExact(encode(t, vector.Context), &decoded) || !validContext(decoded) ||
					settingsFingerprint(decoded) != vector.Expected || previousContextFingerprint(decoded) != vector.Expected {
					t.Fatal("context hash disagrees with the independently selected complete message")
				}
			})
			t.Run("stale_anchor_pin", func(t *testing.T) {
				changed := vector.Context
				changed.Anchor.Hash = strings.Repeat("b", 64)
				if validContext(changed) {
					t.Fatal("changed anchor retained the selected fingerprint")
				}
			})
			t.Run("stale_schedule_pin", func(t *testing.T) {
				changed := vector.Context
				hash := strings.Repeat("c", 64)
				changed.Producer.ScheduleHash = &hash
				if validContext(changed) {
					t.Fatal("changed schedule retained the selected fingerprint")
				}
			})
		})
	}
}

var consumerContextFingerprintSink string

// Digest-function observations only. Fixtures, JSON decoding, file/process
// work and validation are outside the timed loop. Both implementations must
// match a preselected Python SHA3-256 digest on every measured operation.
func BenchmarkConsumerContextFingerprint(b *testing.B) {
	for _, vector := range contextFingerprintVectors(b) {
		input, err := hex.DecodeString(vector.EncodedInput)
		if err != nil {
			b.Fatal(err)
		}
		for _, mode := range []string{"previous", "streamed"} {
			hash := previousContextFingerprint
			if mode == "streamed" {
				hash = settingsFingerprint
			}
			b.Run(vector.Name+"/"+mode, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for b.Loop() {
					actual := hash(vector.Context)
					if actual != vector.Expected {
						b.Fatal("measured context hash changed its selected digest")
					}
					consumerContextFingerprintSink = actual
				}
			})
		}
	}
}

// The complete previous function body is copied unchanged from the selected
// base source. It is a benchmark reference, not a shared production encoder.
func previousContextFingerprint(c settings) string {
	domain := "zenon-spv/verification-context/v1\x00"
	if c.Version == 2 {
		domain = "zenon-spv/verification-context/v2\x00"
	}
	raw := []byte(domain)
	u64 := func(v uint64) { raw = binary.BigEndian.AppendUint64(raw, v) }
	text := func(v string) { u64(uint64(len(v))); raw = append(raw, v...) }
	hash := func(v string) { b, _ := hex.DecodeString(v); raw = append(raw, b...) }
	u64(uint64(c.Version))
	u64(c.Anchor.ChainID)
	u64(c.Anchor.Height)
	hash(c.Anchor.Hash)
	u64(c.Policy.W)
	if c.Version == 2 {
		u64(uint64(*c.Policy.RetainHeaders))
	}
	for _, limit := range resourceLimits(c) {
		u64(uint64(limit))
	}
	if c.Profile == nil {
		u64(0)
	} else {
		u64(1)
		u64(uint64(c.Profile.Version))
		u64(c.Profile.ValidThrough)
		u64(c.Profile.V2FromHeight)
	}
	text(c.Producer.Mode)
	text(c.Producer.Source)
	text(c.Producer.Kind)
	if c.Producer.ScheduleHash == nil {
		u64(0)
	} else {
		u64(1)
		hash(*c.Producer.ScheduleHash)
	}
	u64(uint64(len(c.Checkpoints)))
	for _, cp := range c.Checkpoints {
		u64(cp.Height)
		hash(cp.Hash)
	}
	digest := sha3.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
