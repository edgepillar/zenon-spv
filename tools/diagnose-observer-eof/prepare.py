#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare an explicit diagnostic Go overlay; never edit the selected sources.

This is instrumentation, not a verifier fix or ordinary-build qualification.
The caller supplies new owned scratch and supervises any later Go commands.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = "cc8c73fa75eced453ede7e6f8467042b3f8e14ed"
PINS = {
    "tools/observe-block/main.go": "5f00d19c2979dc9305d452c932933a0d9ed8268bc6712c93eb8b377beac56d91",
    "tools/observe-block/process.go": "595c77cdd74283e26fb3459ded4ace1008dbbd0cafe423f8fde4ad708f03839c",
    "internal/conformance/cli_observer_test.go": "6b47550029b7008829e6dd74e9a5e2c83f8aa57f3e8aa11c7dd49a34b57be6a7",
    "internal/conformance/cli_observer_resources_test.go": "7bf55782e4dd298aa2358a8868cdb3ca26c6f55dc5d984427adb7bac5a790949",
    "internal/conformance/cli_query_test.go": "cab3fd2cb048569165c0ccf04674f9a88abff63436df50240c5c70fd4876dc39",
}


def require(condition):
    if not condition:
        raise ValueError("diagnostic source or workspace selection refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 128 << 10)
    raw = path.read_bytes()
    after = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(len(raw) == st.st_size and identity(after) == identity(st))
    return raw


def unlinked_path(path):
    path = Path(os.path.abspath(path))
    for parent in [path] + list(path.parents):
        if parent.exists() or parent.is_symlink():
            require(not parent.is_symlink())
    return path


def changes(relative, definitions):
    if relative == "tools/observe-block/main.go":
        return [("type observation struct {\n", "type observation struct {\n\tPipeDiagnostic *pipeDiagnostic `json:\"pipe_diagnostic,omitempty\"`\n")]
    if relative == "tools/observe-block/process.go":
        return [
            ("type boundedOutput struct {\n", "type boundedOutput struct {\n\ttrace pipeStreamDiagnostic\n"),
            ("type observedEOFReader struct {\n", "type observedEOFReader struct {\n\ttrace *pipeStreamDiagnostic\n"),
            ("\tn, err := r.input.Read(raw)\n", "\tn, err := r.input.Read(raw)\n\tif r.trace != nil {\n\t\tr.trace.ReadCalls++\n\t\tif err != nil { r.trace.TerminalRead = diagnosticError(err) }\n\t}\n"),
            ("\tw.readEOF = false\n\treader := &observedEOFReader{input: input}\n",
             "\tw.readEOF = false\n\tw.trace = pipeStreamDiagnostic{Started: true, TerminalRead: \"none\"}\n\tstarted := time.Now()\n\treader := &observedEOFReader{input: input, trace: &w.trace}\n"),
            ("\tw.readEOF = err == nil && reader.eof\n",
             "\tw.readEOF = err == nil && reader.eof\n\tw.trace.Completed, w.trace.RealEOF = true, w.readEOF\n\tw.trace.CopyError, w.trace.ElapsedNS = diagnosticError(err), time.Since(started).Nanoseconds()\n"),
            ("\terr := cmd.Run()\n\terr = joinedCopyError(err, out, diagnostics)\n",
             "\trawRunError := cmd.Run()\n\terr := joinedCopyError(rawRunError, out, diagnostics)\n"),
            ("\tif cmd.ProcessState != nil {\n", "\tr.PipeDiagnostic = joinedDiagnostic(rawRunError, err, out, diagnostics, parent, ctx)\n\tif cmd.ProcessState != nil {\n"),
        ]
    if relative == "internal/conformance/cli_observer_test.go":
        return [("type observerProcessRecord struct {\n", definitions + "\ntype observerProcessRecord struct {\n\tPipeDiagnostic *pipeDiagnostic `json:\"pipe_diagnostic,omitempty\"`\n")]
    if relative == "internal/conformance/cli_query_test.go":
        return [("\targs := []string{\"build\", \"-p\", \"1\", \"-trimpath\", \"-o\", binDir + string(os.PathSeparator)}\n",
                 "\targs := []string{\"build\", \"-p\", \"1\", \"-trimpath\", \"-o\", binDir + string(os.PathSeparator)}\n\toverlay := os.Getenv(\"SPV_OBSERVER_EOF_OVERLAY\")\n\tif overlay == \"\" { panic(\"diagnostic overlay not selected\") }\n\targs = append(args, \"-overlay\", overlay)\n")]
    if relative == "internal/conformance/cli_observer_resources_test.go":
        before = "\t\t\t\t\tobservations := make([]processObservation, concurrency)\n"
        # All joined slots survive even when the ordinary validator stops at
        # the first refusal. Do not change that validator or its pass criteria.
        after = before + """\t\t\t\t\tfor slot, result := range results {
\t\t\t\t\t\tvar report observerResourceSummary
\t\t\t\t\t\tdecodeErr := json.Unmarshal(result.stdout, &report)
\t\t\t\t\t\traw, err := json.Marshal(observerResourceFailureContext(round, slot, failures[slot] != nil, result, report, decodeErr == nil))
\t\t\t\t\t\tif err != nil { t.Fatal("cannot encode fixed pipe diagnostic") }
\t\t\t\t\t\tt.Logf("observer-eof-diagnostic-attempt %s", raw)
\t\t\t\t\t}
"""
        return [(before, after)]
    raise ValueError("unselected diagnostic file")


def transform(relative, raw, definitions):
    require(relative in PINS and sha(raw) == PINS[relative])
    transformed = raw.decode("utf-8")
    edits = changes(relative, definitions)
    for before, after in edits:
        require(transformed.count(before) == 1)
        transformed = transformed.replace(before, after, 1)
    inverse = transformed
    for before, after in reversed(edits):
        require(inverse.count(after) == 1)
        inverse = inverse.replace(after, before, 1)
    require(inverse.encode() == raw)
    return transformed.encode()


def prepare(root, destination):
    root, destination = unlinked_path(root), unlinked_path(destination)
    require(root.is_dir() and destination.parent.is_dir() and not destination.exists())
    require(root != destination and root not in destination.parents and destination not in root.parents)
    originals = {}
    for relative, digest in PINS.items():
        path = unlinked_path(root / relative)
        originals[relative] = regular(path)
        require(sha(originals[relative]) == digest)
    templates = {name: regular(HERE / name) for name in ("pipe_diagnostics.go.txt", "pipe_diagnostics_test.go.txt")}
    definitions = templates["pipe_diagnostics.go.txt"].decode().split("// BEGIN TYPES\n")[1].split("// END TYPES\n")[0]
    modified = {name: transform(name, raw, definitions) for name, raw in originals.items()}
    modified["tools/observe-block/zz_eof_diagnostic.go"] = templates["pipe_diagnostics.go.txt"]
    modified["tools/observe-block/zz_eof_diagnostic_test.go"] = templates["pipe_diagnostics_test.go.txt"]
    for name in modified.keys() - originals.keys():
        require(not (root / name).exists() and not (root / name).is_symlink())
    destination.mkdir(mode=0o700)
    mapping, pins = {}, {}
    for index, (relative, raw) in enumerate(modified.items()):
        target = destination / (str(index) + ".go")
        with target.open("xb") as out:
            out.write(raw)
        mapping[str(root / relative)] = str(target)
        pins[relative] = {"sha256": sha(raw), "bytes": len(raw)}
    (destination / "overlay.json").write_text(json.dumps({"Replace": mapping}, sort_keys=True) + "\n", encoding="utf-8")
    require(all(regular(root / name) == raw for name, raw in originals.items()))
    manifest = {
        "schema_version": 1, "kind": "observer-eof-diagnostic-overlay", "selected_base": BASE,
        "original_sha256": PINS, "overlay_files": pins,
        "existing_source_bytes_unchanged": True, "whole_file_patch_inverses_verified": True,
        "ordinary_build_or_release_qualification": False, "verifier_acceptance_changed": False,
        "observer_timeout_seconds": 30, "pipe_wait_delay_seconds": 1,
        "retained_headers": 4096, "targets": 16, "concurrency": 4, "rounds": 21,
        "failure_policy": "retain all joined slots; stop at first failed round; no retries or filtering",
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = prepare(args.source_root, args.destination)
    except (OSError, ValueError, UnicodeError, IndexError):
        print("diagnostic preparation refused", file=sys.stderr)
        return 2
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
