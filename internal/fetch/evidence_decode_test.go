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

func TestRPCStopsBeforeExcessEvidenceDecode(t *testing.T) {
	for _, tc := range []struct {
		name, field       string
		frontier, account bool
	}{
		{name: "frontier content", field: "content", frontier: true},
		{name: "range content", field: "CONTENT"},
		{name: "range descendants", field: `descendantBlock\u017f`, account: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := fmt.Sprintf(`{"%s":[%s"PRIVATE_UNREACHED_MEMBER"]}`, tc.field, strings.Repeat("null,", 100_000))
			result := `{"list":[` + row + `]}`
			if tc.frontier {
				result = row
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, result)
			}))
			defer server.Close()
			client := NewClient(server.URL)
			var err error
			switch {
			case tc.frontier:
				h, fetchErr := client.FetchFrontier(context.Background())
				err = fetchErr
				if !h.HeaderHash.IsZero() {
					t.Fatal("oversized content returned a header")
				}
			case tc.account:
				blocks, fetchErr := client.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 10, 1)
				err = fetchErr
				if len(blocks) != 0 {
					t.Fatal("oversized descendants returned blocks")
				}
			default:
				headers, fetchErr := client.FetchByHeightDetailed(context.Background(), 10, 1)
				err = fetchErr
				if len(headers) != 0 {
					t.Fatal("oversized content returned headers")
				}
			}
			if !errors.Is(err, ErrResponseTooComplex) || !strings.Contains(err.Error(), "decoded entry limit") {
				t.Fatalf("RPC did not stop before decoding excess evidence: %v (cause %T)", err, errors.Unwrap(errors.Unwrap(err)))
			}
			if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), server.URL) {
				t.Fatal("limit failure exposed a private peer value")
			}
		})
	}
}

func TestRPCEvidenceLimitsAndCompatibility(t *testing.T) {
	for _, raw := range []string{
		`null`, `{}`, `{"content":null,"descendantBlocks":null}`,
		`{"content":[],"descendantBlocks":[]}`,
		`{"content":[null,{}],"descendantBlocks":[null,{}]}`,
		`{"CONTEN\u0054":[{"address":"z1","height":10,"hash":"01"}],"descendantBlock\u017f":[{"hash":"02"}]}`,
		`{"version":2,"nextFusionPrice":10,"nextWorkPrice":20,"height":10,"data":"AQ==","signature":"Ag==","publicKey":"Aw=="}`,
		`{"momentumAcknowledged":{"hash":"03","height":10},"amount":"3","tokenStandard":"zts","toAddress":"z1"}`,
		`{"content":[],"trace":{"content":[1,2,3]},"trace":null,"hash":"01","HASH":"02"}`,
	} {
		for _, limit := range []int{2, math.MaxInt} {
			var wantMomentum rpcMomentum
			var wantAccount rpcAccountBlock
			if err := json.Unmarshal([]byte(raw), &wantMomentum); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(raw), &wantAccount); err != nil {
				t.Fatal(err)
			}
			d := &rpcEvidenceDecoder{maxMembers: limit, remaining: limit}
			gotMomentum := rpcMomentum{Height: 77}
			if err := json.Unmarshal([]byte(raw), d.momentum(&gotMomentum)); err != nil || !reflect.DeepEqual(gotMomentum, wantMomentum) || d.remaining != limit-len(wantMomentum.Content) {
				t.Fatalf("bounded momentum changed JSON semantics or count: %v", err)
			}
			d = &rpcEvidenceDecoder{maxMembers: limit, remaining: limit}
			gotAccount := rpcAccountBlock{Height: 77}
			if err := json.Unmarshal([]byte(raw), d.account(&gotAccount)); err != nil || !reflect.DeepEqual(gotAccount, wantAccount) || d.remaining != limit-len(wantAccount.DescendantBlocks) {
				t.Fatalf("bounded account changed JSON semantics or count: %v", err)
			}
		}
	}
}

func TestRPCEvidenceFailuresLeaveTargetsUnchanged(t *testing.T) {
	for _, field := range []string{"content", "descendantBlocks"} {
		for _, tc := range []struct {
			name, raw      string
			perList, total int
			cause          error
		}{
			{"per list", `{"%s":[null,"PRIVATE_UNREACHED_MEMBER"]}`, 1, 10, ErrResponseTooComplex},
			{"total", `{"%s":[null,"PRIVATE_UNREACHED_MEMBER"]}`, 10, 1, ErrResponseTooComplex},
			{"zero total", `{"%s":["PRIVATE_UNREACHED_MEMBER"]}`, 10, 0, ErrResponseTooComplex},
			{"zero list", `{"%s":["PRIVATE_UNREACHED_MEMBER"]}`, 0, 10, ErrResponseTooComplex},
			{"invalid kind", `{"%s":{}}`, 2, 2, ErrInvalidRPCResponse},
			{"invalid member", `{"%s":["PRIVATE_INVALID_MEMBER"]}`, 2, 2, nil},
			{"invalid scalar", `{"%s":[],"height":"PRIVATE_INVALID_HEIGHT"}`, 2, 2, nil},
		} {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				d := &rpcEvidenceDecoder{maxMembers: tc.perList, remaining: tc.total}
				m := rpcMomentum{Height: 77}
				b := rpcAccountBlock{Height: 77}
				target := d.momentum(&m)
				if field == "descendantBlocks" {
					target = d.account(&b)
				}
				err := json.Unmarshal([]byte(fmt.Sprintf(tc.raw, field)), target)
				if err == nil || tc.cause != nil && !errors.Is(err, tc.cause) ||
					!reflect.DeepEqual(m, rpcMomentum{Height: 77}) || !reflect.DeepEqual(b, rpcAccountBlock{Height: 77}) {
					t.Fatalf("failed nested decode returned evidence or wrong category: %v", err)
				}
				if strings.Contains(callFailure("unmarshal result", err).Error(), "PRIVATE") {
					t.Fatal("ordinary decode diagnostics disclosed a private value")
				}
			})
		}
		for _, first := range []string{`null`, `[]`, `[null]`} {
			m := rpcMomentum{Height: 77}
			b := rpcAccountBlock{Height: 77}
			d := newRPCEvidenceDecoder()
			target := d.momentum(&m)
			alias := `CONTEN\u0054`
			if field == "descendantBlocks" {
				target, alias = d.account(&b), `DESCENDANTBLOCK\u017f`
			}
			raw := fmt.Sprintf(`{"%s":%s,"%s":[]}`, field, first, alias)
			if err := json.Unmarshal([]byte(raw), target); !errors.Is(err, ErrInvalidRPCResponse) ||
				!reflect.DeepEqual(m, rpcMomentum{Height: 77}) || !reflect.DeepEqual(b, rpcAccountBlock{Height: 77}) {
				t.Fatalf("replaced evidence field was accepted: %v", err)
			}
		}
	}
}

func TestRPCEvidenceBudgetSpansRangeRows(t *testing.T) {
	for _, total := range []int{3, 4} {
		for _, account := range []bool{false, true} {
			d := &rpcEvidenceDecoder{maxMembers: 2, remaining: total}
			field := "content"
			m := []rpcMomentum{{Height: 77}}
			b := []rpcAccountBlock{{Height: 77}}
			var target any = &rpcListDecoder[rpcMomentum]{target: &m, count: 4, rowTarget: d.momentum}
			if account {
				field = "descendantBlocks"
				target = &rpcListDecoder[rpcAccountBlock]{target: &b, count: 4, rowTarget: d.account}
			}
			raw := fmt.Sprintf(`{"list":[{"%s":[null,{}]},{"%s":null},{"%s":[{},{}]},{"%s":[]}]}`, field, field, field, field)
			err := json.Unmarshal([]byte(raw), target)
			if total == 3 {
				if !errors.Is(err, ErrResponseTooComplex) || !reflect.DeepEqual(m, []rpcMomentum{{Height: 77}}) || !reflect.DeepEqual(b, []rpcAccountBlock{{Height: 77}}) {
					t.Fatalf("later row bypassed aggregate bound or exposed earlier rows: %v", err)
				}
			} else if err != nil || d.remaining != 0 || (!account && len(m) != 4) || (account && len(b) != 4) {
				t.Fatalf("exact aggregate bound failed: %v", err)
			}
		}
	}
}

func TestRPCEvidenceCountsOnlyOuterMembers(t *testing.T) {
	for _, member := range []string{
		`null`, `{}`, `{"hash":"quote\" slash\\ comma, brackets[] braces{}","extension":[null,{"nested":[[],[1,2]]}]}`,
	} {
		for _, limit := range []int{1, 2} {
			for _, field := range []string{"content", "descendantBlocks"} {
				d := &rpcEvidenceDecoder{maxMembers: limit, remaining: 2}
				var m rpcMomentum
				var b rpcAccountBlock
				target := d.momentum(&m)
				if field == "descendantBlocks" {
					target = d.account(&b)
				}
				raw := fmt.Sprintf("{\"%s\":[\n\t%s ,\r\n%s ]}", field, member, member)
				err := json.Unmarshal([]byte(raw), target)
				if limit == 1 {
					if !errors.Is(err, ErrResponseTooComplex) || len(m.Content)+len(b.DescendantBlocks) != 0 {
						t.Fatalf("second outer member bypassed cap: %v", err)
					}
				} else if err != nil || d.remaining != 0 || len(m.Content)+len(b.DescendantBlocks) != 2 {
					t.Fatalf("nested data or quoted delimiters changed outer member count: %v", err)
				}
			}
		}
	}
}

func TestRPCEvidencePreservesWholeJSONValidation(t *testing.T) {
	for _, raw := range []string{
		`{"content":[]} {}`, `{"content":[{},]}`, `{"descendantBlocks":[{},]}`,
		`{"content":[],"extension":` + strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000) + "}",
	} {
		var m rpcMomentum
		var b rpcAccountBlock
		for _, target := range []any{newRPCEvidenceDecoder().momentum(&m), newRPCEvidenceDecoder().account(&b)} {
			var syntax *json.SyntaxError
			if err := json.Unmarshal([]byte(raw), target); !errors.As(err, &syntax) {
				t.Fatalf("nested evidence bypassed whole-object syntax validation: %v", err)
			}
		}
	}
}

func FuzzRPCNestedEvidence(f *testing.F) {
	for _, raw := range []string{
		`null`, `{}`, `{"list":null}`, `{"list":[{}]}`,
		`{"list":[{"content":[null,{}]},{"CONTENT":[{}]}]}`,
		`{"list":[{"descendantBlocks":[null,{}]},{"descendantBlock\u017f":[{}]}]}`,
		`{"list":[{"content":null,"CONTENT":[]}]}`,
		`{"list":[{"descendantBlocks":[],"descendantBlocks":null}]}`,
		`{"list":[{"content":["PRIVATE"],"descendantBlocks":["PRIVATE"]}]}`,
		`{"list":[{"content":[{"hash":"quote\" slash\\ comma, [] {}","extension":[{},[1,2]]}]}]}`,
		`{"list":[{"descendantBlocks":[{"hash":"quote\" slash\\ comma, [] {}","extension":[{},[1,2]]}]}]}`,
	} {
		for _, account := range []bool{false, true} {
			f.Add([]byte(raw), uint8(2), uint8(3), account)
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte, perByte, totalByte uint8, account bool) {
		if len(raw) > 4096 {
			t.Skip()
		}
		perList, total := int(perByte%5), int(totalByte%9)
		d := &rpcEvidenceDecoder{maxMembers: perList, remaining: total}
		m := []rpcMomentum{{Height: 77}}
		b := []rpcAccountBlock{{Height: 77}}
		var target any = &rpcListDecoder[rpcMomentum]{target: &m, count: 8, rowTarget: d.momentum}
		if account {
			target = &rpcListDecoder[rpcAccountBlock]{target: &b, count: 8, rowTarget: d.account}
		}
		if err := json.Unmarshal(raw, target); err != nil {
			if !reflect.DeepEqual(m, []rpcMomentum{{Height: 77}}) || !reflect.DeepEqual(b, []rpcAccountBlock{{Height: 77}}) {
				t.Fatal("failed nested range decode exposed partial output")
			}
			return
		}
		used := 0
		var counts []int
		if account {
			var expected rpcAccountBlockList
			if err := json.Unmarshal(raw, &expected); err != nil || !reflect.DeepEqual(b, expected.List) || len(b) > 8 {
				t.Fatalf("bounded account decode changed JSON semantics: %v", err)
			}
			for _, row := range b {
				counts = append(counts, len(row.DescendantBlocks))
			}
		} else {
			var expected rpcMomentumList
			if err := json.Unmarshal(raw, &expected); err != nil || !reflect.DeepEqual(m, expected.List) || len(m) > 8 {
				t.Fatalf("bounded momentum decode changed JSON semantics: %v", err)
			}
			for _, row := range m {
				counts = append(counts, len(row.Content))
			}
		}
		for _, count := range counts {
			if count > perList {
				t.Fatal("nested list exceeded its bound")
			}
			used += count
		}
		if used > total || d.remaining != total-used {
			t.Fatal("nested rows bypassed the response budget")
		}
	})
}
