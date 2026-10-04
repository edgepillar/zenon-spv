package main

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/0x3639/zenon-spv/internal/fetch"
)

type collectionConfiguration struct {
	binary, hash, rpc, height, count, commitments, segments, momentumHeights string
}

// A local file and a single explicitly selected RPC are mutually exclusive.
// No frontier, checkpoint, implicit endpoint, quorum or renewal is selected.
func validCollectionSelection(c configuration, seen map[string]bool, retention int) bool {
	names := []string{"collector", "collector-sha256", "rpc", "height", "count", "commitments", "segments", "momentum-heights"}
	if seen["bundle"] {
		for _, name := range names {
			if seen[name] {
				return false
			}
		}
		return true
	}
	for _, name := range names[:5] {
		if !seen[name] {
			return false
		}
	}
	endpoint, err := url.Parse(c.collection.rpc)
	if err != nil || !digest(c.collection.hash) || len(c.collection.rpc) > 4096 || endpoint.Hostname() == "" ||
		(endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Fragment != "" {
		return false
	}
	height, err := strconv.ParseInt(c.collection.height, 10, 64)
	if err != nil || height <= 0 {
		return false
	}
	count, err := strconv.Atoi(c.collection.count)
	if err != nil || count < 1 || count > retention || height <= int64(count) {
		return false
	}
	if seen["momentum-heights"] {
		if _, err := fetch.ParseMomentumHeights(c.collection.momentumHeights, uint64(height)-uint64(count), uint64(height)); err != nil {
			return false
		}
	}
	if c.command == "verify-segment" {
		return seen["segments"] && !seen["commitments"] && validTargetArgument(c.collection.segments)
	}
	return seen["commitments"] && !seen["segments"] && validTargetArgument(c.collection.commitments)
}

func validTargetArgument(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 32<<10
}

func collectionArguments(c configuration) []string {
	args := []string{"--rpc", c.collection.rpc, "--height", c.collection.height, "--count", c.collection.count,
		"--proof-only", "--out", "-", "--timeout", c.timeout.String()}
	if c.collection.momentumHeights != "" {
		args = append(args, "--momentum-heights", c.collection.momentumHeights)
	}
	if c.command == "verify-segment" {
		return append(args, "--segments", c.collection.segments)
	}
	return append(args, "--commitments", c.collection.commitments)
}
