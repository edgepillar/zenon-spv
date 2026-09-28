package verify

import (
	"fmt"
	"reflect"
	"testing"
)

func TestProducerAuthorization_UnsupportedModeRefuses(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	policy := Policy{W: 2}
	initial := NewHeaderState(genesis, policy)
	verified, retained := VerifyHeaders(headers, initial, policy)
	if verified.Outcome != OutcomeAccept {
		t.Fatalf("fixture verification failed: %s", verified)
	}
	for _, mode := range []ProducerAuthMode{-1, 2, 255} {
		for _, auth := range []ProducerAuthorizer{nil, staticProducerAuthorizer{decision: ProducerAuthorized}} {
			t.Run(fmt.Sprintf("mode=%d/authorizer=%t", mode, auth != nil), func(t *testing.T) {
				opts := VerifyOptions{Policy: policy, ProducerAuth: ProducerAuthOptions{Mode: mode, Authorizer: auth}}
				r, after := VerifyHeadersWithOptions(headers, initial, opts)
				assertProducerRefusal(t, r)
				if !reflect.DeepEqual(after, initial) {
					t.Fatal("unsupported authorization mode advanced header state")
				}
				assertProducerRefusal(t, AuthorizeRetainedWindow(retained, opts))
				assertProducerRefusal(t, AuthorizeRetainedWindow(initial, opts))
			})
		}
	}
}

type boundaryProducerAuthorizer struct {
	decision   ProducerDecision
	failHeight uint64
	calls      int
}

func (a *boundaryProducerAuthorizer) Authorize(height, timestamp uint64, publicKey []byte) ProducerDecision {
	a.calls++
	if height == a.failHeight {
		return a.decision
	}
	return ProducerAuthorized
}

func (a *boundaryProducerAuthorizer) Source() ProducerSource {
	return ProducerSourceOperatorAttested
}

func TestProducerAuthorization_UnsupportedDecisionRefuses(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	policy := Policy{W: 2}
	verified, initial := VerifyHeaders(headers[:2], NewHeaderState(genesis, policy), policy)
	if verified.Outcome != OutcomeAccept {
		t.Fatalf("fixture prefix failed verification: %s", verified)
	}
	verified, retained := VerifyHeaders(headers[2:], initial, policy)
	if verified.Outcome != OutcomeAccept {
		t.Fatalf("fixture extension failed verification: %s", verified)
	}
	for _, decision := range []ProducerDecision{-1, 3, 255} {
		t.Run(fmt.Sprintf("decision=%d", decision), func(t *testing.T) {
			auth := &boundaryProducerAuthorizer{decision: decision, failHeight: headers[3].Height}
			opts := VerifyOptions{Policy: policy, ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth}}
			r, after := VerifyHeadersWithOptions(headers[2:], initial, opts)
			assertProducerRefusal(t, r)
			if !reflect.DeepEqual(after, initial) || auth.calls != 2 {
				t.Fatalf("invalid decision advanced state or did not stop immediately: calls=%d", auth.calls)
			}
			auth.calls, auth.failHeight = 0, retained.RetainedWindow[1].Height
			assertProducerRefusal(t, AuthorizeRetainedWindow(retained, opts))
			if auth.calls != 2 {
				t.Fatalf("retained authorization continued after invalid decision: calls=%d", auth.calls)
			}
		})
	}
}

func assertProducerRefusal(t *testing.T, r Result) {
	t.Helper()
	if r.Outcome != OutcomeRefused || r.Reason != ReasonProducerSetUnknown || len(r.Proven) != 0 {
		t.Errorf("expected producer authorization refusal without proven guarantees: %s", r)
	}
}
