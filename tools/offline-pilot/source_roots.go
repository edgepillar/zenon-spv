package main

import (
	"errors"
	"strings"
)

const sourceEnumerationGroup = "compiled-source-enumeration/v1"
const sourceEnumerationTest = "TestCompiledPilotSourceEnumeration"
const sourceEnumerationPackage = modulePath + "/tools/offline-pilot"
const sourceEnumerationSubtests = 6

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

type sourceRootCollector struct {
	result  sourceRootResult
	pending int
}

func newSourceRootCollector() *sourceRootCollector {
	return &sourceRootCollector{result: sourceRootResult{
		Package: sourceEnumerationPackage, Test: sourceEnumerationTest, Status: "missing",
	}}
}

// The suite collector validates event lifecycle, package inventory and complete
// input before these counters can contribute to a successful receipt. A root
// completion cannot be inferred from aggregate test counts or a compiled file.
func (c *sourceRootCollector) event(e testEvent) error {
	if c == nil || e.Package != sourceEnumerationPackage {
		return nil
	}
	root, _, nested := strings.Cut(e.Test, "/")
	if root != sourceEnumerationTest {
		return nil
	}
	if !nested {
		switch e.Action {
		case "run":
			c.result.Status = "running"
		case "pass", "fail", "skip":
			if c.pending != 0 {
				return errors.New("source root completed before its subtests")
			}
			c.result.Status = e.Action
		}
		return nil
	}
	if c.result.Status != "running" {
		return errors.New("source subtest outside its root execution")
	}
	switch e.Action {
	case "run":
		c.pending++
	case "pass":
		c.pending--
		c.result.Passed++
	case "skip":
		c.pending--
		c.result.Skipped++
	case "fail":
		c.pending--
		c.result.Failed++
	}
	return nil
}

func (c *sourceRootCollector) complete() bool {
	return c == nil || c.pending == 0 && c.result.Status == "pass" && c.result.Passed == sourceEnumerationSubtests &&
		c.result.Skipped == 0 && c.result.Failed == 0
}

func (c *sourceRootCollector) snapshot() *sourceRootEvidence {
	if c == nil {
		return nil
	}
	status := "incomplete"
	if c.complete() {
		status = "complete"
	}
	return &sourceRootEvidence{Format: "zenon-source-root-controls/v1", Group: sourceEnumerationGroup,
		Status: status, Roots: []sourceRootResult{c.result}}
}
