package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/types"
)

// These compact vectors expand a public recipe using node types and hashing.
// They are serialization stress inputs, not node-executed account blocks or
// evidence that a network momentum can contain this many account headers.
func writeContentScalingVectors() error {
	const prefix = "synthetic flat content member:"
	type sample struct {
		Members int               `json:"members"`
		Targets []expectedContent `json:"targets"`
		Headers []expectedHeader  `json:"headers"`
	}
	c := struct {
		FormatVersion int      `json:"format_version"`
		Source        source   `json:"source"`
		Anchor        anchor   `json:"anchor"`
		MemberPrefix  string   `json:"member_prefix"`
		MemberAddress string   `json:"member_address"`
		Samples       []sample `json:"samples"`
	}{FormatVersion: 1, Source: source{
		Repository: "https://github.com/zenon-network/go-zenon",
		Commit:     nodeCommit, ModuleVersion: nodeVersion, ModuleSum: nodeSum,
	}, MemberPrefix: prefix}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Public test seed.
	address := types.PubKeyToAddress(key.Public().(ed25519.PublicKey))
	c.MemberAddress = hex.EncodeToString(address.Bytes())
	checkpoint := types.NewHash([]byte("synthetic flat content checkpoint"))
	c.Anchor = anchor{ChainID: 99, Height: 6000, Hash: checkpoint.String()}
	for _, count := range []int{1, 1000, 100000} {
		content := make(nom.MomentumContent, count)
		for i := range content {
			input := binary.BigEndian.AppendUint64([]byte(prefix), uint64(i+1))
			content[i] = &types.AccountHeader{Address: address,
				HashHeight: types.HashHeight{Height: uint64(i + 1), Hash: types.NewHash(input)}}
		}
		sort.Slice(content, nom.AccountBlockHeaderComparer(content))
		s := sample{Members: count}
		for _, i := range []int{0, count / 2, count - 1} {
			h := content[i]
			s.Targets = append(s.Targets, expectedContent{Address: c.MemberAddress, Height: h.Height, Hash: h.Hash.String()})
		}
		previous := checkpoint
		for i := range 7 {
			m := baseMomentum()
			m.Version, m.Height, m.PreviousHash = 2, 6001+uint64(i), previous
			m.TimestampUnix += uint64(i) * 10
			m.NextFusionPrice, m.NextWorkPrice = 1000, 1000
			if i == 0 {
				m.Content = content
			}
			v := makeVector("", m, key)
			s.Headers = append(s.Headers, v.Header)
			previous = m.Hash
		}
		c.Samples = append(c.Samples, s)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}
