package fetch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func checkOptionalBase64(t testing.TB, encoded string) {
	t.Helper()
	want, wantErr := base64ToBytesOptionalReference(encoded)
	got, gotErr := base64ToBytesOptional(encoded)
	if !bytes.Equal(got, want) || (got == nil) != (want == nil) ||
		reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
		t.Fatal("optional decoding differs in bytes, nil result, error type or corruption offset")
	}
	if len(encoded) > optionalBase64SizingThreshold {
		n := len(encoded) - strings.Count(encoded, "\r") - strings.Count(encoded, "\n")
		if cap(got) > base64.StdEncoding.DecodedLen(n) {
			t.Fatal("ignored line endings inflated output capacity")
		}
	}
}

func loadOptionalBase64Account(t testing.TB) rpcAccountBlock {
	t.Helper()
	raw, err := os.ReadFile("testdata/mainnet_account_block.json")
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result rpcAccountBlockList `json:"result"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || len(response.Result.List) != 1 {
		t.Fatal("invalid captured account fixture")
	}
	return response.Result.List[0]
}

func paddedOptionalBase64(encoded string) string {
	// Include line endings within quanta and next to padding, not only a prefix.
	return strings.Repeat("\r\n", 2048) + strings.Join(strings.Split(encoded, ""), "\r\n") + "\n\r"
}

func TestRPCOptionalBase64WhitespaceContract(t *testing.T) {
	t.Run("encoded_shapes_and_capacity", func(t *testing.T) {
		for _, size := range []int{0, 1, 2, 3, 31, 32, 33, 63, 64, 65, 3072, 3073} {
			encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, size))
			checkOptionalBase64(t, encoded)
			checkOptionalBase64(t, paddedOptionalBase64(encoded))
			for _, total := range []int{4095, 4096, 4097} {
				if len(encoded) <= total {
					checkOptionalBase64(t, strings.Repeat("\n", total-len(encoded))+encoded)
				}
			}
		}
		checkOptionalBase64(t, strings.Repeat("\r\n", 1<<19))
	})
	t.Run("corruptions_and_partial_results", func(t *testing.T) {
		prefix := strings.Repeat("\r\n", 2048)
		key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
		for _, invalid := range []string{"!", " ", "\t", "\x00", "\xff", "-", "_", "é", `\r\n`} {
			checkOptionalBase64(t, prefix+invalid+key)
			checkOptionalBase64(t, key+prefix+invalid)
			checkOptionalBase64(t, prefix+"AAAA"+invalid+key)
		}
		for _, encoded := range []string{"A", "AA", "AAA", "=AAA", "AA=A", "AA=\r\n=A", "AAAA=", "AAAA===", "AB==", "AAB=", key[:len(key)-2]} {
			checkOptionalBase64(t, prefix+encoded)
			checkOptionalBase64(t, encoded+prefix)
		}
	})
	t.Run("node_account_and_momentum_conversion", func(t *testing.T) {
		account := loadOptionalBase64Account(t)
		want, err := convertAndVerifyAccountBlock(account)
		if err != nil || !ed25519.Verify(want.PublicKey, want.BlockHash[:], want.Signature) {
			t.Fatal("captured account did not preserve its signed envelope")
		}
		account.PublicKey = paddedOptionalBase64(account.PublicKey)
		account.Signature = paddedOptionalBase64(account.Signature)
		got, err := convertAndVerifyAccountBlock(account)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("line endings changed the captured account conversion")
		}
		raw, err := os.ReadFile("../testdata/conformance/momentum-v1-v2.json")
		if err != nil {
			t.Fatal(err)
		}
		type vector struct {
			Momentum rpcMomentum  `json:"momentum"`
			Header   chain.Header `json:"header"`
		}
		var corpus struct {
			FormatVersion int                        `json:"format_version"`
			Source        struct{ Commit string }    `json:"source"`
			Vectors       []vector                   `json:"vectors"`
			Chain         struct{ Vectors []vector } `json:"chain"`
			Transition    struct{ Vectors []vector } `json:"transition"`
		}
		if json.Unmarshal(raw, &corpus) != nil || corpus.FormatVersion != 1 ||
			corpus.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" ||
			len(corpus.Vectors) != 9 || len(corpus.Chain.Vectors) != 6 || len(corpus.Transition.Vectors) != 6 {
			t.Fatal("unexpected pinned momentum corpus")
		}
		vectors := append(append(corpus.Vectors, corpus.Chain.Vectors...), corpus.Transition.Vectors...)
		for _, v := range vectors {
			v.Momentum.PublicKey = paddedOptionalBase64(v.Momentum.PublicKey)
			v.Momentum.Signature = paddedOptionalBase64(v.Momentum.Signature)
			got, err := convertAndVerifyDetailed(v.Momentum)
			if err != nil || !reflect.DeepEqual(got.Header, v.Header) ||
				!ed25519.Verify(got.Header.PublicKey, got.Header.HeaderHash[:], got.Header.Signature) {
				t.Fatal("line endings changed a node-derived v1/v2 momentum")
			}
		}
	})
	t.Run("response_budget_and_private_failures", func(t *testing.T) {
		account := loadOptionalBase64Account(t)
		account.PublicKey = paddedOptionalBase64(account.PublicKey)
		account.Signature = paddedOptionalBase64(account.Signature)
		encode := func(block rpcAccountBlock) []byte {
			raw, err := json.Marshal(struct {
				JSONRPC string              `json:"jsonrpc"`
				ID      int                 `json:"id"`
				Result  rpcAccountBlockList `json:"result"`
			}{"2.0", 1, rpcAccountBlockList{List: []rpcAccountBlock{block}}})
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		raw := encode(account)
		client := NewClient("https://example.invalid/private-endpoint-marker")
		client.HTTP.Transport = optionalBase64Transport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
		})
		for _, limit := range []int64{int64(len(raw)) - 1, int64(len(raw))} {
			budget := &rpcResponseBudget{remaining: limit}
			out := json.RawMessage(`"unchanged"`)
			err := client.callWithBudget(context.Background(), "ledger.getAccountBlocksByHeight", []any{}, &out, budget)
			if limit < int64(len(raw)) {
				if !errors.Is(err, ErrResponseTooLarge) || string(out) != `"unchanged"` {
					t.Fatal("line endings bypassed the response budget")
				}
			} else if err != nil || budget.remaining != 0 {
				t.Fatal("line endings were not fully charged to the response budget")
			}
		}
		got, err := client.FetchAccountBlocksByHeight(context.Background(), account.Address, account.Height, 1)
		if err != nil || len(got) != 1 || !ed25519.Verify(got[0].PublicKey, got[0].BlockHash[:], got[0].Signature) {
			t.Fatal("padded wire strings failed the captured account workflow")
		}
		account.PublicKey = strings.Repeat("\r\n", 2048) + "!private-value-marker"
		raw = encode(account)
		got, err = client.FetchAccountBlocksByHeight(context.Background(), account.Address, account.Height, 1)
		var corruption base64.CorruptInputError
		if err == nil || len(got) != 0 || !errors.As(err, &corruption) || corruption != 4096 ||
			strings.Contains(err.Error(), "private-value-marker") || strings.Contains(err.Error(), "private-endpoint-marker") {
			t.Fatal("corrupt wire strings supplied partial evidence or exposed peer input")
		}
	})
	t.Run("owned_and_concurrent_outputs", func(t *testing.T) {
		want := bytes.Repeat([]byte{0x55}, 32)
		encoded := paddedOptionalBase64(base64.StdEncoding.EncodeToString(want))
		var group sync.WaitGroup
		failed := make(chan bool, 16)
		for i := 0; i < cap(failed); i++ {
			group.Add(1)
			go func() {
				defer group.Done()
				got, err := base64ToBytesOptional(encoded)
				if err != nil || !bytes.Equal(got, want) {
					failed <- true
					return
				}
				got[0] ^= 1
				other, err := base64ToBytesOptional(encoded)
				failed <- err != nil || !bytes.Equal(other, want)
			}()
		}
		group.Wait()
		close(failed)
		for bad := range failed {
			if bad {
				t.Fatal("decoding reused mutable output or changed the original input")
			}
		}
	})
}

type optionalBase64Transport func(*http.Request) (*http.Response, error)

func (transport optionalBase64Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func FuzzRPCOptionalBase64MatchesReference(f *testing.F) {
	for _, seed := range []string{"", "AA==", "AB==", "AAB=", "\r\n", "AA=\r\n=A", paddedOptionalBase64("AQIDBA=="), strings.Repeat("\n", 4097) + "!"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		if len(encoded) > 512<<10 {
			t.Skip("bounded fuzz input")
		}
		checkOptionalBase64(t, encoded)
	})
}
