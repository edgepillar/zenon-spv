package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestRangeQueriesStopBeforeExcessRowDecode(t *testing.T) {
	for _, field := range []string{"list", "LIST", `li\u017ft`} {
		t.Run(field, func(t *testing.T) {
			raw := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"%s":[null,"PRIVATE_UNREACHED_ROW"]}}`, field)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, raw) }))
			defer server.Close()
			client := NewClient(server.URL)
			check := func(n int, err error) {
				t.Helper()
				if n != 0 || !errors.Is(err, ErrQueryMismatch) {
					t.Fatalf("excess range row reached conversion: count=%d err=%v", n, err)
				}
				if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), server.URL) {
					t.Fatal("count refusal disclosed a private peer value")
				}
			}
			headers, err := client.FetchByHeight(context.Background(), 10, 1)
			check(len(headers), err)
			detailed, err := client.FetchByHeightDetailed(context.Background(), 10, 1)
			check(len(detailed), err)
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 10, 1)
			check(len(blocks), err)
		})
	}
}

func TestRangeQueriesRejectReplacedLists(t *testing.T) {
	for _, first := range []string{`null`, `[]`, `[null]`} {
		t.Run(first, func(t *testing.T) {
			momentum, err := json.Marshal(emptyContentMomentum(10))
			if err != nil {
				t.Fatal(err)
			}
			block, err := json.Marshal(queryAccountBlock(t, 10, zeroQueryAddress))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct{ Method string }
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				row := momentum
				if request.Method == "ledger.getAccountBlocksByHeight" {
					row = block
				}
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"list":%s,"LI\u017fT":[%s]}}`, first, row)
			}))
			defer server.Close()
			client := NewClient(server.URL)
			headers, err := client.FetchByHeight(context.Background(), 10, 1)
			if len(headers) != 0 || !errors.Is(err, ErrInvalidRPCResponse) {
				t.Fatalf("later list hid an earlier momentum list: count=%d err=%v", len(headers), err)
			}
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 10, 1)
			if len(blocks) != 0 || !errors.Is(err, ErrInvalidRPCResponse) {
				t.Fatalf("later list hid an earlier account list: count=%d err=%v", len(blocks), err)
			}
		})
	}
}

func TestRangeDecodeLimitsAndCompatibility(t *testing.T) {
	for _, raw := range []string{
		`null`, `{}`, `{"list":null}`, `{"list":[]}`, `{"list":[null,{}]}`,
		`{"LIST":[{"height":10},{"height":11}]}`, `{"li\u017ft":[{}]}`,
		`{"count":9999,"more":true,"list":[{}],"extension":{"list":[1,2,3]}}`,
		`{"trace":0,"trace":1,"list":[{}]}`,
	} {
		var expected rpcMomentumList
		if err := json.Unmarshal([]byte(raw), &expected); err != nil {
			t.Fatal(err)
		}
		for _, limit := range []uint64{2, math.MaxUint64} {
			var got []rpcMomentum
			if err := json.Unmarshal([]byte(raw), &rpcListDecoder[rpcMomentum]{target: &got, count: limit}); err != nil || !reflect.DeepEqual(got, expected.List) {
				t.Fatalf("valid range interpretation changed: %v", err)
			}
		}
	}
	for _, tc := range []struct {
		raw   string
		limit uint64
		cause error
	}{
		{`{"list":[null,"PRIVATE_UNREACHED_ROW"]}`, 1, ErrQueryMismatch},
		{`{"list":[{}]}`, 0, ErrQueryMismatch},
		{`{"list":[{}],"LIST":null}`, 1, ErrInvalidRPCResponse},
		{`{"list":null,"list":[]}`, 1, ErrInvalidRPCResponse},
		{`{"list":{}}`, 1, ErrInvalidRPCResponse},
	} {
		got := []rpcMomentum{{Height: 77}}
		err := json.Unmarshal([]byte(tc.raw), &rpcListDecoder[rpcMomentum]{target: &got, count: tc.limit})
		if !errors.Is(err, tc.cause) || !reflect.DeepEqual(got, []rpcMomentum{{Height: 77}}) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("range error mutated output or lost its safe classification: %v", err)
		}
	}
}

func TestRangeDecodeRetainsWholeJSONValidation(t *testing.T) {
	for _, raw := range []string{
		`{"list":[{}]} {}`, `{"list":[{},]}`, `{"list":[{}],"extension":}`,
		`{"list":[],"extension":` + strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000) + "}",
	} {
		got := []rpcMomentum{{Height: 77}}
		var syntax *json.SyntaxError
		err := json.Unmarshal([]byte(raw), &rpcListDecoder[rpcMomentum]{target: &got, count: 1})
		if !errors.As(err, &syntax) || !reflect.DeepEqual(got, []rpcMomentum{{Height: 77}}) {
			t.Fatalf("range parsing bypassed JSON syntax validation: %v", err)
		}
	}
}

func FuzzRPCRangeDecode(f *testing.F) {
	for _, raw := range []string{
		`null`, `{}`, `{"list":null}`, `{"list":[]}`, `{"list":[{},null]}`,
		`{"list":[{"height":10}],"count":100}`, `{"li\u017ft":[{}]}`,
		`{"list":[],"LIST":[{}]}`, `{"list":[{},"PRIVATE"]}`, `{"list":[{},]}`,
	} {
		f.Add([]byte(raw), uint8(1))
	}
	f.Fuzz(func(t *testing.T, raw []byte, capByte uint8) {
		if len(raw) > 4096 {
			t.Skip()
		}
		limit := uint64(capByte % 8)
		got := []rpcMomentum{{Height: 77}}
		err := json.Unmarshal(raw, &rpcListDecoder[rpcMomentum]{target: &got, count: limit})
		if err != nil {
			if !reflect.DeepEqual(got, []rpcMomentum{{Height: 77}}) {
				t.Fatal("failed range decode changed existing output")
			}
			return
		}
		var expected rpcMomentumList
		if err := json.Unmarshal(raw, &expected); err != nil || !reflect.DeepEqual(got, expected.List) || uint64(len(got)) > limit {
			t.Fatalf("bounded range changed JSON semantics or exceeded its count: %v", err)
		}
	})
}
