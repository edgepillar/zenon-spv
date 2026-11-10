package main

import (
	"errors"
	"strings"
)

const sourceEnumerationGroup = "compiled-source-enumeration/v1"
const compiledNativeObserverGroup = "compiled-native-observers/v1"
const sourceEnumerationTest = "TestCompiledPilotSourceEnumeration"
const sourceEnumerationPackage = modulePath + "/tools/offline-pilot"
const sourceEnumerationSubtests = 6

type sourceRootSpec struct {
	packageName string
	test        string
	subtests    int
}

var sourceEnumerationRoot = sourceRootSpec{sourceEnumerationPackage, sourceEnumerationTest, sourceEnumerationSubtests}

var sourceRootGroups = map[string][]sourceRootSpec{
	sourceEnumerationGroup: {sourceEnumerationRoot},
	compiledNativeObserverGroup: {
		{modulePath + "/internal/conformance", "TestCompiledAdvancingBlockObserver", 9},
		{modulePath + "/internal/conformance", "TestCompiledNodeAccountBasicObserver", 58},
		{modulePath + "/internal/conformance", "TestCompiledNodeAccountReceiveObserver", 52},
		sourceEnumerationRoot,
	},
}

type sourceRootResult struct {
	Package string `json:"package"`
	Test    string `json:"test"`
	Status  string `json:"status"`
	Passed  int    `json:"passed_subtests"`
	Skipped int    `json:"skipped_subtests"`
	Failed  int    `json:"failed_subtests"`
}

// This fixed source-owned group discloses no caller-selected names, dynamic
// subtest labels, output, timestamps or paths. The enclosing receipt binds it
// to the complete stream, selected report, source and process outcome.
type sourceRootEvidence struct {
	Format string             `json:"format"`
	Group  string             `json:"group"`
	Status string             `json:"status"`
	Roots  []sourceRootResult `json:"roots"`
}

type sourceRootObservation struct {
	result   sourceRootResult
	expected int
	pending  int
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
			result:   sourceRootResult{Package: spec.packageName, Test: spec.test, Status: "missing"},
			expected: spec.subtests,
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
			return row.observe(e.Action, nested)
		}
	}
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
				row.result.Skipped != 0 || row.result.Failed != 0 {
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
	roots := make([]sourceRootResult, len(c.roots))
	for i, row := range c.roots {
		roots[i] = row.result
	}
	return &sourceRootEvidence{Format: "zenon-source-root-controls/v1", Group: c.group, Status: status, Roots: roots}
}
