package fetch

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRPCConversionDiagnosticsDoNotEchoRemoteValues(t *testing.T) {
	for _, field := range []string{"content", "address", "toAddress", "tokenStandard"} {
		t.Run(field, func(t *testing.T) {
			privateValue := strings.Repeat(privateDiagnosticMarker+"/", 512) + "1qqqqqq"
			momentum := emptyContentMomentum(99)
			block := queryAccountBlock(t, 1, zeroQueryAddress)
			switch field {
			case "content":
				momentum["content"] = []any{map[string]any{"address": privateValue, "height": 1, "hash": strings.Repeat("0", 64)}}
			case "address":
				block.Address = privateValue
			case "toAddress":
				block.ToAddress = privateValue
			case "tokenStandard":
				block.TokenStandard = privateValue
			}
			server := httptest.NewServer((&fakeRPC{responses: map[string]any{
				"ledger.getFrontierMomentum":      momentum,
				"ledger.getMomentumsByHeight":     map[string]any{"list": []any{momentum}},
				"ledger.getAccountBlocksByHeight": rpcAccountBlockList{List: []rpcAccountBlock{block}},
			}}).handler(t))
			defer server.Close()
			client := NewClient(privatePeerURL(server.URL))
			multi := NewMultiClient([]string{privatePeerURL(server.URL), privatePeerURL(server.URL) + "2"})
			check := func(name string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s accepted malformed evidence", name)
				}
				formatted := fmt.Sprintf("%v %+v %s", err, err, err)
				if strings.Contains(formatted, privateDiagnosticMarker) || strings.Contains(formatted, server.URL) || len(formatted) > 2048 {
					t.Fatalf("%s disclosed or expanded an untrusted conversion value", name)
				}
				if !strings.HasPrefix(name, "multi") {
					var wrapped *rpcCallFailure
					if !errors.As(err, &wrapped) || !strings.Contains(wrapped.Unwrap().Error(), privateDiagnosticMarker) {
						t.Fatal("conversion failure lost the cause available to explicit private inspection")
					}
				}
			}
			if field == "content" {
				h, err := client.FetchFrontier(context.Background())
				check("frontier", err)
				if !h.HeaderHash.IsZero() {
					t.Fatal("failed frontier returned evidence")
				}
				headers, err := client.FetchByHeight(context.Background(), 99, 1)
				check("headers", err)
				detailed, err := client.FetchByHeightDetailed(context.Background(), 99, 1)
				check("detailed", err)
				if len(headers)+len(detailed) != 0 {
					t.Fatal("failed range returned evidence")
				}
				_, err = multi.FetchByHeight(context.Background(), 99, 1)
				check("multi headers", err)
				_, err = multi.FetchByHeightDetailed(context.Background(), 99, 1)
				check("multi detailed", err)
				_, err = multi.FetchFrontierAtAgreedHeight(context.Background(), 0)
				check("multi frontier", err)
			} else {
				blocks, err := client.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 1, 1)
				check("account blocks", err)
				if len(blocks) != 0 {
					t.Fatal("failed account query returned evidence")
				}
				_, err = multi.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 1, 1)
				check("multi account blocks", err)
			}
		})
	}
}

func TestRPCConversionRetainsCodecErrorType(t *testing.T) {
	momentum := emptyContentMomentum(99)
	momentum["data"] = "?"
	block := queryAccountBlock(t, 1, zeroQueryAddress)
	block.Data = "?"
	server := httptest.NewServer((&fakeRPC{responses: map[string]any{
		"ledger.getFrontierMomentum":      momentum,
		"ledger.getAccountBlocksByHeight": rpcAccountBlockList{List: []rpcAccountBlock{block}},
	}}).handler(t))
	defer server.Close()
	client := NewClient(server.URL)
	_, momentumErr := client.FetchFrontier(context.Background())
	_, accountErr := client.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 1, 1)
	for _, err := range []error{momentumErr, accountErr} {
		var corrupt base64.CorruptInputError
		if !errors.As(err, &corrupt) || corrupt != 0 || !strings.Contains(err.Error(), "rpc convert") {
			t.Fatalf("conversion wrapper lost the codec type or stage: %v", err)
		}
	}
}
