package conformance_test

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestCompiledPeerHelpOmitsEnvironmentEndpoints(t *testing.T) {
	bins := buildQueryCLIs(t)
	for _, command := range []string{"watch", "fetch-bundle"} {
		for _, flag := range []string{"--help", "--unknown-option"} {
			t.Run(command+"/"+flag, func(t *testing.T) {
				binary, args, code := bins["fetch-bundle"], []string{flag}, 1
				if command == "watch" {
					binary, args, code = bins["zenon-spv"], []string{"watch", flag}, 64
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, args...)
				cmd.Env = append(queryCLIEnvironment(),
					"ZENON_SPV_RPC=https://PRIVATE_ENV_USER:PRIVATE_ENV_PASSWORD@PRIVATE_ENV_HOST.invalid/PRIVATE_ENV_PATH?token=PRIVATE_ENV_TOKEN",
					"ZENON_SPV_PEERS=https://PRIVATE_ENV_PEER_A.invalid,https://PRIVATE_ENV_PEER_B.invalid")
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				_ = cmd.Run()
				if ctx.Err() != nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != code || stdout.Len() != 0 {
					t.Fatal("help or invalid syntax changed exit/stream behavior")
				}
				if command == "watch" && flag == "--unknown-option" {
					if stderr.String() != "arguments: invalid command syntax\n" {
						t.Fatal("watch syntax did not use the fixed private diagnostic")
					}
				} else if !bytes.Contains(stderr.Bytes(), []byte("ZENON_SPV_RPC")) {
					t.Fatal("explicit help or collector usage lost its peer configuration text")
				}
				if bytes.Contains(stderr.Bytes(), []byte("PRIVATE_ENV")) {
					t.Fatal("help disclosed an environment endpoint or credential")
				}
			})
		}
	}
}
