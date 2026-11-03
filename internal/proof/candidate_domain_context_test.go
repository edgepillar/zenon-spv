// SPDX-License-Identifier: MIT

package proof_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

type candidateDomainRecordVector struct {
	Name   string
	Packed string `json:"packed_hex"`
	Fields struct {
		DomainClass, RuntimeKind                            uint8
		StfSpecHash                                         chain.Hash
		InputSource, ExecProfile, ForeignProfile            uint8
		ProfileConfigHex, ChainBindingHex                   string
		MinExecutors, ProposerPolicy, FinalityModel, Status uint8
	}
}

type candidateDomainFacts struct {
	Format string
	Source struct {
		Repository, Revision, Tree string
		Files                      map[string]json.RawMessage
	}
	Harness struct {
		Path, SHA256 string
		Bytes        int64
	}
	Execution struct {
		Test, Platform, Go string
		CGO                bool   `json:"cgo_enabled"`
		RecordSHA256       string `json:"record_sha256"`
		GateSHA256         string `json:"gate_sha256"`
		Exit               int    `json:"actual_exit"`
		Complete           bool
		ABICases           int    `json:"original_ABI_cases_passed"`
		SubkeyPairs        int    `json:"original_subkey_pairs_passed"`
		PythonEncodings    int    `json:"independent_python_encodings_matched"`
		PythonSubkeys      int    `json:"independent_python_subkeys_matched"`
		LoadedModules      int    `json:"loaded_modules_verified"`
		FullModuleGraph    string `json:"full_module_graph_go_mod_verify"`
	}
	Scope                map[string]bool
	SettlementAddressHex string `json:"settlement_address_hex"`
	Records              []candidateDomainRecordVector
	Configs              []struct {
		Name                                 string
		Packed                               string `json:"packed_hex"`
		WithdrawalDelay, RuntimeUpgradeDelay uint64
	}
	Subkeys []struct {
		Name            string
		Domain          uint32 `json:"domain_id"`
		RecordSubkeyHex string `json:"record_subkey_hex"`
		ConfigSubkeyHex string `json:"config_subkey_hex"`
	}
	IndependentFullKeys []struct {
		Name       string
		Domain     uint32     `json:"domain_id"`
		RecordKey  string     `json:"record_ledger_key_hex"`
		ConfigKey  string     `json:"config_ledger_key_hex"`
		RecordPath chain.Hash `json:"record_path_hex"`
		ConfigPath chain.Hash `json:"config_path_hex"`
	} `json:"independent_full_keys"`
}

func candidateDomainVectors(t testing.TB) candidateDomainFacts {
	t.Helper()
	// The reader bounds regular-file bytes and verifies the complete digest.
	// Keep this helper available to fuzz seeds without creating on-disk fixtures.
	raw := candidateDomainPinned(t, "../testdata/conformance/domain-context-abi.json", 20285,
		"eb062c1377bdb9a07605ada1269480fc563508083f011bfdce05c322cd7d8955")
	var facts candidateDomainFacts
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&facts); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		t.Fatal("trailing original domain-context facts")
	}
	wantScope := map[string]bool{
		"synthetic": true, "original_node_ABI_executed": true, "original_node_subkeys_executed": true,
		"original_full_ledger_keys_executed": false, "independent_python_full_keys": true,
		"node_chain_started": false, "network_execution": false, "profile_agreed": false,
		"state_value_acceptance": false, "submission_time_config_established": false,
		"settlement_or_finality_established": false,
	}
	e := facts.Execution
	if facts.Format != "zenon-candidate-domain-context-facts/v1" || len(facts.Records) != 8 || len(facts.Configs) != 4 || len(facts.Subkeys) != 4 || len(facts.IndependentFullKeys) != 4 ||
		facts.Source.Repository != "digitalSloth/go-zenon" || facts.Source.Revision != "938fca3b7787da86827a5eb63371509b36e14761" ||
		facts.Source.Tree != "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4" || len(facts.Source.Files) != 13 || !reflect.DeepEqual(facts.Scope, wantScope) ||
		e.Test != "TestSPVDomainContextEncoding" || e.Platform != "darwin/arm64" || e.Go != "go1.25.14" || e.CGO || e.Exit != 0 || !e.Complete ||
		e.ABICases != 12 || e.SubkeyPairs != 4 || e.PythonEncodings != 12 || e.PythonSubkeys != 8 || e.LoadedModules != 21 || e.FullModuleGraph != "NOT_ESTABLISHED" ||
		e.RecordSHA256 != "b9a7f79f2c518c384bd3d7d67bf318bb383ab670373ba7e29c51e6b00afb9c4d" ||
		e.GateSHA256 != "7f8b5230187f366393b343e5d98d026dcf4556c656eb76a2a1d3985763e39f32" {
		t.Fatal("original source, execution and candidate-only scope changed")
	}
	if facts.Harness.Path != "tools/gen-state-root-vectors/domain-context-abi_test.go.txt" || facts.Harness.Bytes != 5453 ||
		facts.Harness.SHA256 != "050c4ab29737fc9e4a6acf2981712be433e88176ae7eecc9bd875c1c039ffbfc" {
		t.Fatal("original domain-context harness identity changed")
	}
	candidateDomainPinned(t, "../../"+facts.Harness.Path, facts.Harness.Bytes, facts.Harness.SHA256)
	return facts
}

func candidateDomainPinned(t testing.TB, path string, size int64, want string) []byte {
	t.Helper()
	f, err := os.Open(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close recorded domain-context input: %v", err)
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		t.Fatal("recorded domain-context input length or type changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, size+1))
	digest := sha256.Sum256(raw)
	if err != nil || int64(len(raw)) != size || hex.EncodeToString(digest[:]) != want {
		t.Fatal("recorded domain-context input digest changed")
	}
	return raw
}

func candidateDomainHex(t testing.TB, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func candidateDomainLimits() proof.CandidateDomainRecordLimits {
	return proof.CandidateDomainRecordLimits{MaxValueBytes: 4096, MaxProfileConfigBytes: 256, MaxChainBindingBytes: 256, MaxDynamicBytes: 512}
}

func candidateDomainWant(t testing.TB, v candidateDomainRecordVector) proof.CandidateDomainRecord {
	t.Helper()
	f := v.Fields
	return proof.CandidateDomainRecord{
		DomainClass: f.DomainClass, RuntimeKind: f.RuntimeKind, StfSpecHash: f.StfSpecHash,
		InputSource: f.InputSource, ExecProfile: f.ExecProfile, ForeignProfile: f.ForeignProfile,
		ProfileConfig: candidateDomainHex(t, f.ProfileConfigHex), ChainBinding: candidateDomainHex(t, f.ChainBindingHex),
		MinExecutors: f.MinExecutors, ProposerPolicy: f.ProposerPolicy, FinalityModel: f.FinalityModel, Status: f.Status,
	}
}

func TestCandidateDomainContextOriginalEncoding(t *testing.T) {
	facts := candidateDomainVectors(t)
	for _, v := range facts.Records {
		t.Run("record-"+v.Name, func(t *testing.T) {
			got, err := proof.DecodeCandidateDomainRecord(candidateDomainHex(t, v.Packed), candidateDomainLimits())
			if err != nil || !reflect.DeepEqual(got, candidateDomainWant(t, v)) {
				t.Fatalf("domainRecord fields differ from original ABI: %v", err)
			}
		})
	}
	for _, v := range facts.Configs {
		t.Run("config-"+v.Name, func(t *testing.T) {
			got, err := proof.DecodeCandidateDomainConfig(candidateDomainHex(t, v.Packed))
			if err != nil || got != (proof.CandidateDomainConfig{WithdrawalDelay: v.WithdrawalDelay, RuntimeUpgradeDelay: v.RuntimeUpgradeDelay}) {
				t.Fatalf("domainConfig fields differ from original ABI: %v", err)
			}
		})
	}
}

func TestCandidateDomainContextKeys(t *testing.T) {
	facts := candidateDomainVectors(t)
	var address chain.Address
	copy(address[:], candidateDomainHex(t, facts.SettlementAddressHex))
	for i, v := range facts.IndependentFullKeys {
		t.Run(v.Name, func(t *testing.T) {
			subkey := facts.Subkeys[i]
			if subkey.Name != v.Name || subkey.Domain != v.Domain {
				t.Fatal("independent and original subkey identities differ")
			}
			for _, row := range []struct {
				name, wantKey, wantSubkey string
				key                       [27]byte
				path, wantPath            chain.Hash
			}{
				{"record", v.RecordKey, subkey.RecordSubkeyHex, proof.CandidateSettlementDomainRecordKey(address, v.Domain), proof.CandidateSettlementDomainRecordPath(address, v.Domain), v.RecordPath},
				{"config", v.ConfigKey, subkey.ConfigSubkeyHex, proof.CandidateSettlementDomainConfigKey(address, v.Domain), proof.CandidateSettlementDomainConfigPath(address, v.Domain), v.ConfigPath},
			} {
				t.Run(row.name, func(t *testing.T) {
					if hex.EncodeToString(row.key[:]) != row.wantKey || hex.EncodeToString(row.key[22:]) != row.wantSubkey || row.path != row.wantPath {
						t.Fatal("local full key/path differs from independent bytes or original subkey")
					}
					wrongDomain := row.key
					binary.LittleEndian.PutUint32(wrongDomain[23:], v.Domain)
					if v.Domain == 0x01020304 && chain.Hash(sha3.Sum256(wrongDomain[:])) == row.path {
						t.Fatal("little-endian domain substituted for big-endian domain")
					}
					for _, offset := range []int{0, 1, 21, 22, 26} {
						wrong := row.key
						wrong[offset] ^= 1
						if chain.Hash(sha3.Sum256(wrong[:])) == row.path {
							t.Fatal("different namespace, address, prefix or domain reused the path")
						}
					}
					if chain.Hash(sha3.Sum256(row.key[22:])) == row.path || chain.Hash(sha3.Sum256(row.path[:])) == row.path {
						t.Fatal("application subkey or double-hashed path substituted for full ledger key")
					}
				})
			}
		})
	}
}

func TestCandidateDomainContextTruncation(t *testing.T) {
	facts := candidateDomainVectors(t)
	for _, v := range facts.Records {
		t.Run("record-"+v.Name, func(t *testing.T) {
			raw := candidateDomainHex(t, v.Packed)
			for n := 0; n < len(raw); n++ {
				got, err := proof.DecodeCandidateDomainRecord(raw[:n], candidateDomainLimits())
				if err == nil || !reflect.DeepEqual(got, proof.CandidateDomainRecord{}) {
					t.Fatalf("truncated record prefix %d returned a value", n)
				}
			}
		})
	}
	for _, v := range facts.Configs {
		t.Run("config-"+v.Name, func(t *testing.T) {
			raw := candidateDomainHex(t, v.Packed)
			for n := 0; n < len(raw); n++ {
				if got, err := proof.DecodeCandidateDomainConfig(raw[:n]); err == nil || got != (proof.CandidateDomainConfig{}) {
					t.Fatalf("truncated config prefix %d returned a value", n)
				}
			}
		})
	}
}

func candidateDomainRefuse(t *testing.T, raw []byte, limits proof.CandidateDomainRecordLimits, want error) {
	t.Helper()
	got, err := proof.DecodeCandidateDomainRecord(raw, limits)
	if !errors.Is(err, want) || !reflect.DeepEqual(got, proof.CandidateDomainRecord{}) {
		t.Fatalf("invalid record returned a value or wrong error: %v", err)
	}
}

func TestCandidateDomainContextMalformedRecord(t *testing.T) {
	raw := candidateDomainHex(t, candidateDomainVectors(t).Records[4].Packed)
	for _, index := range []int{0, 1, 3, 4, 5, 8, 9, 10, 11} {
		for _, bit := range []int{0, 30} {
			t.Run(fmt.Sprintf("width-%d-%d", index, bit), func(t *testing.T) {
				bad := bytes.Clone(raw)
				bad[index*32+bit] = 1
				candidateDomainRefuse(t, bad, candidateDomainLimits(), proof.ErrCandidateDomainEncoding)
			})
		}
	}
	for _, row := range []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"offset-head", func(b []byte) []byte { binary.BigEndian.PutUint64(b[6*32+24:], 0); return b }, proof.ErrCandidateDomainEncoding},
		{"offset-gap", func(b []byte) []byte { binary.BigEndian.PutUint64(b[6*32+24:], 416); return b }, proof.ErrCandidateDomainEncoding},
		{"offset-unaligned", func(b []byte) []byte { binary.BigEndian.PutUint64(b[6*32+24:], 385); return b }, proof.ErrCandidateDomainEncoding},
		{"offset-alias", func(b []byte) []byte { copy(b[7*32:8*32], b[6*32:7*32]); return b }, proof.ErrCandidateDomainEncoding},
		{"offset-high-bits", func(b []byte) []byte { b[7*32] = 1; return b }, proof.ErrCandidateDomainEncoding},
		{"length-high-bits", func(b []byte) []byte { b[384] = 1; return b }, proof.ErrCandidateDomainEncoding},
		{"length-uint64-max", func(b []byte) []byte {
			for i := 408; i < 416; i++ {
				b[i] = 0xff
			}
			return b
		}, proof.ErrCandidateDomainBounds},
		{"first-padding", func(b []byte) []byte { b[449] = 1; return b }, proof.ErrCandidateDomainEncoding},
		{"second-padding", func(b []byte) []byte { b[545] = 1; return b }, proof.ErrCandidateDomainEncoding},
		{"late-length", func(b []byte) []byte { binary.BigEndian.PutUint64(b[504:], 65); return b }, proof.ErrCandidateDomainEncoding},
		{"trailing-data", func(b []byte) []byte { return append(b, 0) }, proof.ErrCandidateDomainEncoding},
	} {
		t.Run(row.name, func(t *testing.T) {
			candidateDomainRefuse(t, row.edit(bytes.Clone(raw)), candidateDomainLimits(), row.want)
		})
	}
}

func TestCandidateDomainContextLimits(t *testing.T) {
	raw := candidateDomainHex(t, candidateDomainVectors(t).Records[4].Packed)
	for _, row := range []struct {
		name string
		edit func(*proof.CandidateDomainRecordLimits)
	}{
		{"zero-value", func(l *proof.CandidateDomainRecordLimits) { l.MaxValueBytes = 0 }},
		{"below-head", func(l *proof.CandidateDomainRecordLimits) { l.MaxValueBytes = 447 }},
		{"above-ceiling", func(l *proof.CandidateDomainRecordLimits) { l.MaxValueBytes = 4097 }},
		{"zero-profile", func(l *proof.CandidateDomainRecordLimits) { l.MaxProfileConfigBytes = 0 }},
		{"zero-binding", func(l *proof.CandidateDomainRecordLimits) { l.MaxChainBindingBytes = 0 }},
		{"zero-cumulative", func(l *proof.CandidateDomainRecordLimits) { l.MaxDynamicBytes = 0 }},
		{"negative-profile", func(l *proof.CandidateDomainRecordLimits) { l.MaxProfileConfigBytes = -1 }},
		{"negative-binding", func(l *proof.CandidateDomainRecordLimits) { l.MaxChainBindingBytes = -1 }},
		{"negative-cumulative", func(l *proof.CandidateDomainRecordLimits) { l.MaxDynamicBytes = -1 }},
		{"cap-over-value", func(l *proof.CandidateDomainRecordLimits) { l.MaxChainBindingBytes = 4097 }},
		{"whole-value", func(l *proof.CandidateDomainRecordLimits) { l.MaxValueBytes = len(raw) - 1 }},
		{"profile", func(l *proof.CandidateDomainRecordLimits) { l.MaxProfileConfigBytes = 32 }},
		{"binding", func(l *proof.CandidateDomainRecordLimits) { l.MaxChainBindingBytes = 32 }},
		{"cumulative", func(l *proof.CandidateDomainRecordLimits) { l.MaxDynamicBytes = 65 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			limits := candidateDomainLimits()
			row.edit(&limits)
			candidateDomainRefuse(t, raw, limits, proof.ErrCandidateDomainBounds)
		})
	}
	t.Run("exact-caps", func(t *testing.T) {
		limits := proof.CandidateDomainRecordLimits{MaxValueBytes: len(raw), MaxProfileConfigBytes: 33, MaxChainBindingBytes: 33, MaxDynamicBytes: 66}
		if _, err := proof.DecodeCandidateDomainRecord(raw, limits); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("empty-fields-positive-caps", func(t *testing.T) {
		raw := candidateDomainHex(t, candidateDomainVectors(t).Records[0].Packed)
		limits := proof.CandidateDomainRecordLimits{MaxValueBytes: 448, MaxProfileConfigBytes: 1, MaxChainBindingBytes: 1, MaxDynamicBytes: 1}
		if _, err := proof.DecodeCandidateDomainRecord(raw, limits); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("oversized-before-allocation", func(t *testing.T) {
		large := make([]byte, 1<<20)
		limits := candidateDomainLimits()
		var value proof.CandidateDomainRecord
		var err error
		allocations := testing.AllocsPerRun(100, func() { value, err = proof.DecodeCandidateDomainRecord(large, limits) })
		if allocations != 0 || !errors.Is(err, proof.ErrCandidateDomainBounds) || !reflect.DeepEqual(value, proof.CandidateDomainRecord{}) {
			t.Fatal("oversized candidate allocated or returned partial data")
		}
	})
}

func TestCandidateDomainContextConfigCanonical(t *testing.T) {
	raw := candidateDomainHex(t, candidateDomainVectors(t).Configs[2].Packed)
	for _, offset := range []int{0, 23, 32, 55} {
		t.Run(fmt.Sprintf("width-%d", offset), func(t *testing.T) {
			bad := bytes.Clone(raw)
			bad[offset] = 1
			got, err := proof.DecodeCandidateDomainConfig(bad)
			if !errors.Is(err, proof.ErrCandidateDomainEncoding) || got != (proof.CandidateDomainConfig{}) {
				t.Fatal("dirty uint64 upper bits returned a config")
			}
		})
	}
	for _, extra := range []int{1, 32, 4096} {
		t.Run(fmt.Sprintf("trailing-%d", extra), func(t *testing.T) {
			got, err := proof.DecodeCandidateDomainConfig(append(bytes.Clone(raw), make([]byte, extra)...))
			if !errors.Is(err, proof.ErrCandidateDomainEncoding) || got != (proof.CandidateDomainConfig{}) {
				t.Fatal("trailing bytes returned a config")
			}
		})
	}
}

func TestCandidateDomainContextDetached(t *testing.T) {
	raw := candidateDomainHex(t, candidateDomainVectors(t).Records[4].Packed)
	original := bytes.Clone(raw)
	first, err := proof.DecodeCandidateDomainRecord(raw, candidateDomainLimits())
	if err != nil {
		t.Fatal(err)
	}
	second, err := proof.DecodeCandidateDomainRecord(raw, candidateDomainLimits())
	if err != nil {
		t.Fatal(err)
	}
	first.ProfileConfig[0] ^= 1
	if !bytes.Equal(first.ChainBinding, second.ChainBinding) {
		t.Fatal("profile mutation changed the other dynamic field")
	}
	first.ProfileConfig = append(first.ProfileConfig, bytes.Repeat([]byte{0x99}, len(first.ChainBinding))...)
	if !bytes.Equal(first.ChainBinding, second.ChainBinding) {
		t.Fatal("profile capacity aliases the other dynamic field")
	}
	first.ChainBinding[0] ^= 1
	if !bytes.Equal(raw, original) || bytes.Equal(first.ProfileConfig, second.ProfileConfig) || bytes.Equal(first.ChainBinding, second.ChainBinding) {
		t.Fatal("decoded fields alias the input or another result")
	}
	if bytes.Equal(first.ProfileConfig, first.ChainBinding) {
		t.Fatal("independent dynamic fields unexpectedly alias")
	}
	clear(raw)
	if !reflect.DeepEqual(second, candidateDomainWant(t, candidateDomainVectors(t).Records[4])) {
		t.Fatal("input mutation changed a detached result")
	}
}
