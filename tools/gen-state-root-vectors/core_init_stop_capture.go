//go:build candidate_core_init_stop

// SPDX-License-Identifier: GPL-3.0-only
package zenon

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/chain"
)

type candidateInitCall struct {
	Error string `json:"error"`
	Panic string `json:"panic"`
}
type candidateInitObservation struct {
	Case string `json:"case"`
	Init candidateInitCall `json:"Init"`
	Stop candidateInitCall `json:"Stop"`
	ReadyBeforeStop bool `json:"ready_before_Stop"`
	ReadyAfterInit bool `json:"ready_after_Init"`
	ConsensusAfterInit string `json:"consensus_after_Init"`
	StopCompletedBeforeInitRelease bool `json:"Stop_completed_before_Init_release"`
	ExplicitTeardown candidateInitCall `json:"explicit_teardown"`
	ReadyAfterTeardown bool `json:"ready_after_teardown"`
	ConsensusAfterTeardown string `json:"consensus_after_teardown"`
	FirstProtocolClose bool `json:"controlled_first_protocol_close"`
	ControlledInitScheduling bool `json:"controlled_Init_scheduling"`
}
func candidateInitClass(err error) string {
	if err == nil { return "none" }
	if errors.Is(err, ErrStopIncomplete) { return "stop-incomplete" }
	if errors.Is(err, leveldb.ErrClosed) { return "leveldb-closed" }
	if err.Error() == "chain instance is stopped" { return "chain-stopped" }
	return "other:" + err.Error()
}
func candidateInitInvoke(fn func() error) (out candidateInitCall) {
	out.Error = "none"
	defer func() {
		if value := recover(); value != nil { out.Panic = fmt.Sprint(value) }
	}()
	out.Error = candidateInitClass(fn())
	return
}
type candidatePausedInit struct {
	chain.Chain
	entered chan struct{}
	release chan struct{}
}
func (p *candidatePausedInit) Init() error {
	err := p.Chain.Init()
	close(p.entered)
	<-p.release
	return err
}

// CandidateCoreInitStopCapture uses real keyless managers and one declared
// scheduling facade. It makes no promise about unselected Start interleavings.
func CandidateCoreInitStopCapture(cfg *Config, mode string) (out candidateInitObservation, err error) {
	if cfg == nil || cfg.ProducingKeyPair != nil || (mode != "incomplete-Stop" && mode != "overlapping-Init-Stop") {
		return out, errors.New("unselected keyless lifecycle case")
	}
	value, err := NewZenon(cfg)
	if err != nil { return out, err }
	z := value.(*zenon)
	if z.Config().ProducingKeyPair != nil || z.Producer().GetCoinBase() != nil {
		return out, errors.New("keyless constructor invariant")
	}
	out.Case = mode
	if mode == "incomplete-Stop" {
		z.protocol.Stop()
		out.FirstProtocolClose = true
		out.Stop = candidateInitInvoke(z.Stop)
		out.Init = candidateInitInvoke(z.Init)
		out.ReadyAfterInit = z.chain.StateTreeReady()
		out.ConsensusAfterInit = CandidateCoreStopConsensusStatus(z)
		// The first controlled Stop panics before reaching these real managers.
		// Do not re-close protocol or retry the terminal core Stop.
		out.ExplicitTeardown = candidateInitInvoke(func() error {
			return errors.Join(z.pillar.Stop(), z.subscribe.Stop(), z.evPrinter.Stop(),
				z.consensus.Stop(), z.chain.Stop(), z.levelDb.Close())
		})
	} else {
		pause := &candidatePausedInit{Chain:z.chain, entered:make(chan struct{}), release:make(chan struct{})}
		z.chain = pause
		out.ControlledInitScheduling = true
		initResult := make(chan candidateInitCall, 1)
		stopResult := make(chan candidateInitCall, 1)
		stopEntered := make(chan struct{})
		var joined sync.WaitGroup
		joined.Add(2)
		go func() { defer joined.Done(); initResult <- candidateInitInvoke(z.Init) }()
		<-pause.entered
		out.ReadyBeforeStop = pause.Chain.StateTreeReady()
		go func() { defer joined.Done(); close(stopEntered); stopResult <- candidateInitInvoke(z.Stop) }()
		<-stopEntered
		select {
		case out.Stop = <-stopResult:
			out.StopCompletedBeforeInitRelease = true
		case <-time.After(2 * time.Second):
		}
		close(pause.release)
		out.Init = <-initResult
		if !out.StopCompletedBeforeInitRelease { out.Stop = <-stopResult }
		joined.Wait()
		out.ReadyAfterInit = z.chain.StateTreeReady()
		out.ConsensusAfterInit = CandidateCoreStopConsensusStatus(z)
		out.ExplicitTeardown = candidateInitInvoke(z.Stop)
	}
	out.ReadyAfterTeardown = z.chain.StateTreeReady()
	out.ConsensusAfterTeardown = CandidateCoreStopConsensusStatus(z)
	return out, nil
}
