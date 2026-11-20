package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

const sourceEnumerationGroup = "compiled-source-enumeration/v1"
const compiledNativeObserverGroup = "compiled-native-observers/v1"
const compiledNativeObserverGroupV2 = "compiled-native-observers/v2"
const compiledNativeObserverGroupV3 = "compiled-native-observers/v3"
const sourceEnumerationTest = "TestCompiledPilotSourceEnumeration"
const sourceEnumerationPackage = modulePath + "/tools/offline-pilot"
const sourceEnumerationSubtests = 6
const nodeAccountPoWObserverTest = "TestCompiledNodeAccountPoWObserver"

type sourceRootSpec struct {
	packageName string
	test        string
	subtests    int
}

var sourceEnumerationRoot = sourceRootSpec{sourceEnumerationPackage, sourceEnumerationTest, sourceEnumerationSubtests}

var compiledNativeObserverRoots = []sourceRootSpec{
	{modulePath + "/internal/conformance", "TestCompiledAdvancingBlockObserver", 9},
	{modulePath + "/internal/conformance", "TestCompiledNodeAccountBasicObserver", 58},
	{modulePath + "/internal/conformance", "TestCompiledNodeAccountReceiveObserver", 52},
	sourceEnumerationRoot,
}

var compiledNativeObserverRootsV2 = append(slices.Clone(compiledNativeObserverRoots),
	sourceRootSpec{modulePath + "/internal/conformance", nodeAccountPoWObserverTest, 134})

var sourceRootGroups = map[string][]sourceRootSpec{
	sourceEnumerationGroup:        {sourceEnumerationRoot},
	compiledNativeObserverGroup:   compiledNativeObserverRoots,
	compiledNativeObserverGroupV2: compiledNativeObserverRootsV2,
	compiledNativeObserverGroupV3: append(slices.Clone(compiledNativeObserverRootsV2),
		sourceRootSpec{modulePath + "/internal/conformance", "TestCompiledVerifierSelectionGuards", 0},
		sourceRootSpec{modulePath + "/internal/conformance", "TestCompiledVerifierSyntaxPrivacy", 0},
		sourceRootSpec{modulePath + "/internal/conformance", "TestCompiledCollectorSyntaxPrivacy", 0},
		sourceRootSpec{modulePath + "/internal/conformance", "TestCompiledMaintainerSyntaxPrivacy", 0}),
}

type sourceRootReportSpec struct {
	marker string
	size   int
	digest string
}

// Only these complete public reports can reach the retained receipt.
var sourceRootReportSpecs = map[string]sourceRootReportSpec{
	nodeAccountPoWObserverTest:            {"node-account-pow-observer ", 523, "4a41ad86abce3301f54448dafd21901e3c6158fa9dda67dc72a0bed8bc89f1c1"},
	"TestCompiledVerifierSelectionGuards": {"offline-verifier-selection-controls ", 25028, "102b9576a1c178547a4881fefe464c95747752a15a81cea97312b3c384fa8a2f"},
	"TestCompiledVerifierSyntaxPrivacy":   {"offline-verifier-syntax-controls ", 8077, "f50dd105ff0b753742dce19cfba7580748422b2dc029520764bcaba17f8f56a7"},
	"TestCompiledCollectorSyntaxPrivacy":  {"offline-collector-syntax-controls ", 3272, "9e76894c137e91527335e464c58a86fc19a73c798b1a207c68979a788d5666e3"},
	"TestCompiledMaintainerSyntaxPrivacy": {"offline-maintainer-syntax-controls ", 1722, "9ef3f49d5fa9cf7402767943c49440f9f5cb18a950b67115f2d4c485d2605c2d"},
}

type sourceRootResult struct {
	Package string `json:"package"`
	Test    string `json:"test"`
	Status  string `json:"status"`
	Passed  int    `json:"passed_subtests"`
	Skipped int    `json:"skipped_subtests"`
	Failed  int    `json:"failed_subtests"`
}

// The enclosing receipt binds these fixed roots and the bounded reports
// to the complete stream, selected report, source and process outcome.
type sourceRootEvidence struct {
	Format                 string                     `json:"format"`
	Group                  string                     `json:"group"`
	Status                 string                     `json:"status"`
	Roots                  []sourceRootResult         `json:"roots"`
	NodeAccountPoWObserver json.RawMessage            `json:"node_account_pow_observer,omitempty"`
	CLIControls            map[string]json.RawMessage `json:"cli_controls,omitempty"`
}

type sourceRootObservation struct {
	result     sourceRootResult
	expected   int
	pending    int
	reportSpec sourceRootReportSpec
	fragment   []byte
	report     json.RawMessage
}

type sourceRootCollector struct {
	group string
	roots []sourceRootObservation
}

func newSourceRootCollector(group string) *sourceRootCollector {
	specs, ok := sourceRootGroups[group]
	if !ok {
		return nil
	}
	collector := &sourceRootCollector{group: group, roots: make([]sourceRootObservation, len(specs))}
	for i, spec := range specs {
		collector.roots[i] = sourceRootObservation{
			result:     sourceRootResult{Package: spec.packageName, Test: spec.test, Status: "missing"},
			expected:   spec.subtests,
			reportSpec: sourceRootReportSpecs[spec.test],
		}
	}
	return collector
}

// The suite collector validates event lifecycle, package inventory and complete
// input before these counters can contribute to a successful receipt. A root
// completion cannot be inferred from aggregate test counts or a compiled file.
func (c *sourceRootCollector) event(e testEvent) error {
	if c == nil {
		return nil
	}
	root, _, nested := strings.Cut(e.Test, "/")
	for i := range c.roots {
		row := &c.roots[i]
		if e.Package == row.result.Package && root == row.result.Test {
			if err := row.observe(e.Action, nested); err != nil {
				return err
			}
			if row.reportSpec.marker != "" && e.Action == "output" {
				return row.observeReport(e.Output, !nested && row.result.Status == "running")
			}
			return nil
		}
	}
	return nil
}

func (o *sourceRootObservation) observeReport(output string, rootRunning bool) error {
	spec := o.reportSpec
	if o.fragment == nil {
		_, value, found := strings.Cut(output, spec.marker)
		if !found {
			return nil
		}
		output = value
	}
	if !rootRunning || o.report != nil || len(output) > spec.size+2-len(o.fragment) {
		return errors.New("invalid source root report")
	}
	if o.fragment == nil {
		o.fragment = make([]byte, 0, spec.size+2)
	}
	o.fragment = append(o.fragment, output...)
	if !strings.HasSuffix(output, "\n") {
		return nil
	}
	raw := bytes.TrimSuffix(bytes.TrimSuffix(o.fragment, []byte("\n")), []byte("\r"))
	sum := sha256.Sum256(raw)
	if len(raw) != spec.size || hex.EncodeToString(sum[:]) != spec.digest {
		return errors.New("invalid source root report")
	}
	o.report = raw
	o.fragment = nil
	return nil
}

func (o *sourceRootObservation) observe(action string, nested bool) error {
	if !nested {
		switch action {
		case "run":
			o.result.Status = "running"
		case "pass", "fail", "skip":
			if o.pending != 0 {
				return errors.New("source root completed before its subtests")
			}
			if o.fragment != nil {
				return errors.New("source root completed with a partial report")
			}
			o.result.Status = action
		}
		return nil
	}
	if o.result.Status != "running" {
		return errors.New("source subtest outside its root execution")
	}
	switch action {
	case "run":
		o.pending++
	case "pass":
		o.pending--
		o.result.Passed++
	case "skip":
		o.pending--
		o.result.Skipped++
	case "fail":
		o.pending--
		o.result.Failed++
	}
	return nil
}

func (c *sourceRootCollector) complete() bool {
	if c != nil {
		for _, row := range c.roots {
			if row.pending != 0 || row.result.Status != "pass" || row.result.Passed != row.expected ||
				row.result.Skipped != 0 || row.result.Failed != 0 || row.reportSpec.marker != "" && row.report == nil {
				return false
			}
		}
	}
	return true
}

func (c *sourceRootCollector) snapshot() *sourceRootEvidence {
	if c == nil {
		return nil
	}
	status := "incomplete"
	if c.complete() {
		status = "complete"
	}
	evidence := &sourceRootEvidence{
		Format: "zenon-source-root-controls/v1",
		Group:  c.group,
		Status: status,
		Roots:  make([]sourceRootResult, len(c.roots)),
	}
	switch c.group {
	case compiledNativeObserverGroupV2:
		evidence.Format = "zenon-source-root-controls/v2"
	case compiledNativeObserverGroupV3:
		evidence.Format = "zenon-source-root-controls/v3"
		evidence.CLIControls = make(map[string]json.RawMessage)
	}
	for i, row := range c.roots {
		evidence.Roots[i] = row.result
		if row.report == nil {
			continue
		}
		if row.result.Test == nodeAccountPoWObserverTest {
			evidence.NodeAccountPoWObserver = slices.Clone(row.report)
		} else {
			evidence.CLIControls[row.result.Test] = slices.Clone(row.report)
		}
	}
	return evidence
}
