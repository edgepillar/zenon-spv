package fetch

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Independent whole-value standard-library decoding is the hash/error oracle.
func checkRPCDataHash(t *testing.T, encoded string) {
	t.Helper()
	raw, wantErr := base64.StdEncoding.DecodeString(encoded)
	got, err := hashRPCData(encoded)
	if wantErr != nil {
		if got != (chain.Hash{}) || reflect.TypeOf(err) != reflect.TypeOf(wantErr) || err.Error() != wantErr.Error() {
			t.Fatalf("standard Base64 failure contract changed: %v versus %v", err, wantErr)
		}
	} else if err != nil || got != sha3sum(raw) {
		t.Fatalf("locally decoded preimage hash changed: %v", err)
	}
}

func TestRPCDataHashMatchesStandardBase64(t *testing.T) {
	prefix := strings.Repeat("QUJD", 1025)
	for _, tail := range []string{"", "AA==", "AB==", "/z==", "AAA=", "AA==\r\n", "AA==QUJD", "AAA==", "=", "A", "AA", "AAA", " ", "\xff", "PRIVATE_INVALID"} {
		checkRPCDataHash(t, prefix+tail)
	}
	for _, size := range []int{0, 1, 2, 3, 3071, 3072, 3073, 7680, 1 << 20} {
		raw := make([]byte, size)
		for i := range raw {
			raw[i] = byte(i)
		}
		encoded := base64.StdEncoding.EncodeToString(raw)
		checkRPCDataHash(t, encoded)
		checkRPCDataHash(t, strings.Repeat("\r\n", 4096)+encoded+"\r\n")
		for _, cut := range []int{1, 1023, 1024, 1025} {
			if cut < len(encoded) {
				checkRPCDataHash(t, encoded[:cut]+"\r\n"+encoded[cut:])
			}
		}
	}
	// Padding at a reader boundary must not admit a second padded block.
	checkRPCDataHash(t, strings.Repeat("QUJD", 255)+"AA=="+strings.Repeat("QUJD", 1024)+"AA==")
}

func TestRPCDataHashConverterBoundaries(t *testing.T) {
	raw, err := os.ReadFile("testdata/mainnet_account_block.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Result struct{ List []rpcAccountBlock } `json:"result"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || len(fixture.Result.List) != 1 {
		t.Fatalf("load node account fixture: %v", err)
	}
	if _, err := convertAndVerifyAccountBlock(fixture.Result.List[0]); err != nil {
		t.Fatalf("existing node-derived account hash changed: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("synthetic preimage", 4096)))
	preimage, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	h := chain.Header{Version: 1, ChainIdentifier: 1, Height: 42, DataHash: sha3sum(preimage), ContentHash: sha3sum(nil)}
	m := rpcMomentum{Version: 1, ChainIdentifier: 1, Height: 42, Hash: hashHex(h.ComputeHash()), PreviousHash: hashHex(h.PreviousHash), ChangesHash: hashHex(h.ChangesHash), Data: encoded}
	got, err := convertAndVerifyDetailed(m)
	if err != nil || got.Header.DataHash != h.DataHash {
		t.Fatalf("large synthetic momentum preimage changed: %v", err)
	}
	for _, bad := range []string{encoded + "PRIVATE_INVALID", strings.Repeat("QUJD", 1025) + "A"} {
		b := fixture.Result.List[0]
		b.Data, m.Data = bad, bad
		var corrupt base64.CorruptInputError
		if got, err := convertAndVerifyAccountBlock(b); !errors.As(err, &corrupt) || !reflect.DeepEqual(got, chain.AccountBlock{}) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("account data failure leaked a partial block or input: %v", err)
		}
		if got, err := convertAndVerifyDetailed(m); !errors.As(err, &corrupt) || !reflect.DeepEqual(got, DetailedHeader{}) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("momentum data failure leaked a partial header or input: %v", err)
		}
	}
}

func FuzzRPCDataHash(f *testing.F) {
	for _, value := range []string{"", "AA==", "AA==QUJD", "AAA=", "\r\n", "A", "!", "\xff"} {
		f.Add([]byte(value))
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > 4096 {
			t.Skip()
		}
		checkRPCDataHash(t, strings.Repeat("QUJD", 1025)+string(value))
	})
}
