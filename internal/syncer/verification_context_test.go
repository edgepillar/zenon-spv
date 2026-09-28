package syncer

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/verify"
)

type contextTestAuthorizer struct{}

func (contextTestAuthorizer) Source() verify.ProducerSource {
	return verify.ProducerSourceOperatorAttested
}

func (contextTestAuthorizer) Authorize(uint64, uint64, []byte) verify.ProducerDecision {
	return verify.ProducerAuthorized
}

func TestWatchContextReportsCapturedSettingsOnce(t *testing.T) {
	for _, mode := range []string{"default", "enabled", "custom"} {
		t.Run(mode, func(t *testing.T) {
			loop, out, initial := persistenceLoop(t)
			loop.ShowContext = mode != "default"
			loop.Policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: loop.Genesis,
				ValidThrough: 1020, Source: "PRIVATE_PROFILE_SOURCE"}
			initial.ProtocolProfile = loop.Policy.ProtocolProfile
			if err := verify.SaveHeaderState(loop.StatePath, initial); err != nil {
				t.Fatal(err)
			}
			opts := verify.VerifyOptions{Policy: loop.Policy}
			if mode == "custom" {
				loop.Authorizer = contextTestAuthorizer{}
				opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: loop.Authorizer}
			}
			state, err := verify.LoadTrustedState(loop.StatePath, loop.Genesis, opts)
			if err != nil {
				t.Fatal(err)
			}
			want, err := state.VerificationContext()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			saves := 0
			loop.SaveState = func(path string, snapshot verify.HeaderState) error {
				saves++
				cancel()
				return verify.SaveHeaderState(path, snapshot)
			}
			if err := loop.Run(ctx); err != nil || saves != 1 {
				t.Fatalf("context reporting interfered with persisted progress: saves=%d err=%v", saves, err)
			}
			count := 0
			for _, line := range strings.Split(out.String(), "\n") {
				if raw, ok := strings.CutPrefix(line, "verification_context: "); ok {
					var got verify.VerificationContext
					if err := json.Unmarshal([]byte(raw), &got); err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("watch did not report its captured context: %v", err)
					}
					count++
				}
			}
			if (mode == "default" && count != 0) || (mode != "default" && count != 1) {
				t.Fatalf("unexpected number of context reports: %d", count)
			}
			if strings.Contains(out.String(), "PRIVATE_PROFILE_SOURCE") || strings.Contains(out.String(), loop.StatePath) {
				t.Fatal("private metadata reached successful watch output")
			}
		})
	}
}
