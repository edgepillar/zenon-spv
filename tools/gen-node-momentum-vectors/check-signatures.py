#!/usr/bin/env python3
"""Check existing node-corpus signatures with verification-only OpenSSL 3.

Python reconstructs the messages before an independent Ed25519 backend runs.
No generator, signer, wallet, node, SPV executable or RPC client is invoked.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check as BYTES
from check_account import account_bytes

NODE_SOURCE = {
    "repository": "https://github.com/zenon-network/go-zenon",
    "commit": "3a4131e63881058b6ce2ee81d3a41d0033fafc99",
    "module_version": "v0.0.8-alphanet.0.20260924192459-3a4131e63881",
    "module_sum": "h1:7Yf9IL6y7T0gHnRrUs4oulsEcV6YXDRDiIKpUCurCHk=",
}
CORPORA = ("momentum-v1-v2", "account-amounts", "account-segments", "contract-batches",
           "delayed-inclusion", "content-scaling", "historical-testnet-genesis")
ORACLES = ("account-amounts", "account-segments", "contract-batches", "delayed-inclusion",
           "content-scaling", "genesis")
ORDER = 2**252 + 27742317777372353535851937790883648493
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
OPERATION = ("pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", "public-key.der",
             "-in", "message.bin", "-sigfile", "signature.bin", "-provider", "default", "-propquery", "provider=default")
CHECKER_FILES = ("check-signatures.py", "check.py", "check_account.py") + tuple("check-" + name + ".py" for name in ORACLES)


class Refused(Exception):
    def __init__(self, stage, details=None):
        self.stage = stage
        self.details = details
        self.outcomes = []


def require(condition, stage):
    if not condition:
        raise Refused(stage)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@contextlib.contextmanager
def regular_file(path, limit, stage):
    # Reject special files before open: opening a FIFO can wait for a writer.
    selected = path.stat()
    require(stat.S_ISREG(selected.st_mode) and 0 < selected.st_size <= limit, stage)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, stage)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            yield stream, info
    finally:
        if descriptor is not None:
            os.close(descriptor)


def file_hash(path):
    with regular_file(path, 256 * 1024**2, "backend_identity") as (stream, info):
        digest = hashlib.sha256()
        total = 0
        for raw in iter(lambda: stream.read(1024**2), b""):
            total += len(raw)
            require(total <= 256 * 1024**2, "backend_identity")
            digest.update(raw)
        require(total == info.st_size, "backend_identity")
        return digest.hexdigest()


def json_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "corpus_json")
        result[key] = value
    return result


def parse(raw):
    require(len(raw) <= 8 * 1024**2, "corpus_limit")
    corpus = json.loads(raw, object_pairs_hook=json_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(Refused("corpus_json")))
    nodes = 0
    def bound(value, depth=0):
        nonlocal nodes
        nodes += 1
        require(depth <= 32 and nodes <= 100000, "corpus_limit")
        if isinstance(value, dict):
            for child in value.values():
                bound(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                bound(child, depth + 1)
        elif isinstance(value, str):
            require(len(value) <= 1024**2, "corpus_limit")
    bound(corpus)
    require(type(corpus) is dict and type(corpus.get("format_version")) is int and
            corpus["format_version"] == 1 and corpus.get("source") == NODE_SOURCE, "source_pin")
    return corpus


def oracle(name):
    spec = importlib.util.spec_from_file_location("byte_" + name.replace("-", "_"), HERE / ("check-" + name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def decoded(value, nullable=False):
    if value is None and nullable:
        return b""
    require(type(value) is str, "signature_shape")
    return BYTES.base64_bytes(value)


def record(identifier, kind, header, preimage, unsigned=False, invalid_amount=False):
    message = BYTES.digest(preimage)
    require(message == BYTES.hash_bytes(header["hash"]), "preimage")
    key = decoded(header["publicKey"], nullable=unsigned)
    signature = decoded(header["signature"], nullable=unsigned)
    if unsigned:
        require(not key and not signature, "unsigned_signature")
    else:
        require(len(key) == 32 and len(signature) == 64, "signature_shape")
        if kind == "account":
            require((b"\x00" + BYTES.digest(key)[:19]).hex() == header["address"], "account_identity")
        require(int.from_bytes(signature[32:], "little") < ORDER, "signature_scalar")
    return {"id": identifier, "kind": kind, "message": message, "preimage": preimage,
            "key": key, "signature": signature, "unsigned": unsigned, "invalid_amount": invalid_amount}


def projected_preimage(header):
    require(type(header["version"]) is int and header["version"] in (1, 2), "preimage")
    preimage = b"".join((BYTES.uint64(header["version"]), BYTES.uint64(header["chainIdentifier"]),
                        BYTES.hash_bytes(header["previousHash"]), BYTES.uint64(header["height"]),
                        BYTES.uint64(header["timestamp"]), BYTES.hash_bytes(header["dataHash"]),
                        BYTES.hash_bytes(header["contentHash"]), BYTES.hash_bytes(header["changesHash"])))
    fusion, work = BYTES.uint64(header["nextFusionPrice"]), BYTES.uint64(header["nextWorkPrice"])
    return preimage + fusion + work if header["version"] == 2 else preimage


def collect(directory):
    snapshots, identities, records = {}, [], []
    # Parse and snapshot all seven files before any backend execution. Oracles
    # read these snapshots, so a changing input cannot mix wire/projection data.
    for name in CORPORA:
        path = directory / (name + ".json")
        with regular_file(path, 8 * 1024**2, "corpus_file") as (stream, info):
            raw = stream.read(8 * 1024**2 + 1)
            require(len(raw) == info.st_size, "corpus_changed")
        snapshots[name] = (raw, parse(raw))
        identities.append({"name": name + ".json", "sha256": sha(raw), "bytes": len(raw)})
    with tempfile.TemporaryDirectory(prefix="node-signature-bytes-") as temporary:
        root = Path(temporary)
        for name, (raw, _) in snapshots.items():
            (root / (name + ".json")).write_bytes(raw)
        with contextlib.redirect_stdout(io.StringIO()):
            BYTES.check_corpus(snapshots["momentum-v1-v2"][1])
            for name in ORACLES:
                checker = oracle(name)
                corpus_name = "historical-testnet-genesis" if name == "genesis" else name
                if name == "content-scaling":
                    checker.check(snapshots[name][1])
                else:
                    checker.check(root / (corpus_name + ".json"))
    for name, (_, corpus) in snapshots.items():
        def momentum(vector, position, unsigned=False):
            preimage = BYTES.check_vector(vector) if not unsigned else projected_preimage(vector["header"])
            records.append(record(name + "/momentum/" + str(position), "momentum", vector["header"], preimage, unsigned))
        if name == "momentum-v1-v2":
            vectors = corpus["vectors"] + corpus["chain"]["vectors"] + corpus["transition"]["vectors"]
            for i, vector in enumerate(vectors):
                momentum(vector, i)
        elif name in ("account-segments", "contract-batches", "delayed-inclusion"):
            for i, vector in enumerate(corpus["chain"]["vectors"]):
                momentum(vector, i)
            for segment_index, segment in enumerate(corpus["segments"]):
                for i, vector in enumerate(segment["vectors"]):
                    block, rpc = vector["block"], vector["rpc"]
                    _, preimage = account_bytes(block, rpc)
                    require(block["blockType"] in (2, 3, 4, 5), "account_envelope")
                    embedded = block["blockType"] in (4, 5)
                    require(block["address"].startswith("01") == embedded, "account_identity")
                    records.append(record(name + "/account/%d/%d" % (segment_index, i), "account", block, preimage, embedded))
        elif name == "account-amounts":
            for i, vector in enumerate(corpus["vectors"]):
                _, preimage = account_bytes(vector["block"], vector["rpc"])
                require(type(vector["scalar_valid"]) is bool, "account_scalar")
                records.append(record(name + "/account/" + str(i), "account", vector["block"], preimage,
                                      invalid_amount=not vector["scalar_valid"]))
        elif name == "content-scaling":
            for i, sample in enumerate(corpus["samples"]):
                for j, header in enumerate(sample["headers"]):
                    records.append(record(name + "/momentum/%d/%d" % (i, j), "momentum", header, projected_preimage(header)))
        else:
            momentum(corpus["vector"], 0, unsigned=True)
    require(len(records) == 102 and len({row["id"] for row in records}) == 102 and
            sum(not row["unsigned"] for row in records) == 91 and
            sum(row["invalid_amount"] for row in records) == 4, "corpus_coverage")
    return records, identities


def variants(row):
    message, signature = row["message"], row["signature"]
    scalar = int.from_bytes(signature[32:], "little")
    return (("original", message, signature, True),
            ("message-bit", bytes((message[0] ^ 1,)) + message[1:], signature, False),
            ("raw-preimage", row["preimage"], signature, False),
            ("double-SHA3", BYTES.digest(message), signature, False),
            ("signature-bit", message, bytes((signature[0] ^ 1,)) + signature[1:], False),
            ("S-plus-order", message, signature[:32] + (scalar + ORDER).to_bytes(32, "little"), False))


def outcome(process):
    # Key-width errors are refused before OpenSSL; no version-specific key
    # loading diagnostic is treated as an expected signature rejection.
    stdout = process.stdout.replace(b"\r\n", b"\n")
    if process.returncode == 0 and stdout == b"Signature Verified Successfully\n" and not process.stderr:
        return True
    if process.returncode == 1 and stdout == b"Signature Verification Failure\n":
        return False
    raise Refused("backend_outcome")


class Backend:
    def __init__(self, selected, root):
        located = shutil.which(str(selected))
        require(located is not None, "backend_unavailable")
        self.path = Path(located).resolve()
        self.sha256 = file_hash(self.path)
        self.root = root
        (root / "empty.cnf").write_bytes(b"")
        self.env = {"PATH": str(self.path.parent) + os.pathsep + os.defpath,
                    "LC_ALL": "C", "LANG": "C", "OPENSSL_CONF": str(root / "empty.cnf")}
        for name in ("SystemRoot", "WINDIR"):
            if name in os.environ:
                self.env[name] = os.environ[name]
        version = self.call(("version",))
        match = re.match(rb"OpenSSL (3\.[0-9]+\.[0-9]+)\b", version.stdout)
        require(version.returncode == 0 and not version.stderr and match is not None, "backend_version")
        self.version = match.group(1).decode("ascii")

    def call(self, arguments):
        try:
            return subprocess.run([str(self.path), *arguments], cwd=self.root, env=self.env,
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        except subprocess.TimeoutExpired as error:
            raise Refused("backend_deadline", {"returncode": None,
                "stdout_sha256": sha(error.stdout or b""), "stderr_sha256": sha(error.stderr or b"")}) from error
        except OSError as error:
            raise Refused("backend_launch", {"returncode": None,
                "stdout_sha256": sha(b""), "stderr_sha256": sha(b"")}) from error

    def verify(self, key, message, signature):
        require(type(key) is bytes and len(key) == 32 and type(signature) is bytes and len(signature) == 64 and
                type(message) is bytes and 0 < len(message) <= 4096, "signature_shape")
        try:
            (self.root / "public-key.der").write_bytes(SPKI_PREFIX + key)
            (self.root / "message.bin").write_bytes(message)
            (self.root / "signature.bin").write_bytes(signature)
        except OSError as error:
            raise Refused("backend_staging") from error
        process = self.call(OPERATION)
        details = {"returncode": process.returncode,
                   "stdout_sha256": sha(process.stdout), "stderr_sha256": sha(process.stderr)}
        try:
            return outcome(process), details
        except Refused as error:
            error.details = details
            raise

    def identity(self):
        require(file_hash(self.path) == self.sha256, "backend_changed")
        return {"implementation": "OpenSSL", "version": self.version, "executable_sha256": self.sha256,
                "provider": "default", "property_query": "provider=default",
                "empty_config_sha256": sha(b""), "operation": list(OPERATION),
                "executable_origin_and_dynamic_libraries_authenticated": False}


def run(directory, selected, source_revision=None):
    require(source_revision is None or re.fullmatch(r"[0-9a-f]{40}", source_revision) is not None, "source_revision")
    checker_inputs = [{"name": name, "sha256": sha((HERE / name).read_bytes())} for name in CHECKER_FILES]
    rows, corpora = collect(directory)
    outcomes = []
    signed = [row for row in rows if not row["unsigned"]]
    with tempfile.TemporaryDirectory(prefix="node-signature-verify-") as temporary:
        backend = Backend(selected, Path(temporary))
        for row in signed:
            for control, message, signature, expected in variants(row):
                try:
                    actual, details = backend.verify(row["key"], message, signature)
                except Refused as error:
                    if error.details is not None:
                        error.details.update({"id": row["id"], "control": control, "expected": expected,
                                              "actual": None, "error_stage": error.stage})
                        outcomes.append(error.details)
                    error.outcomes = outcomes
                    raise
                details.update({"id": row["id"], "control": control, "expected": expected, "actual": actual})
                outcomes.append(details)
                if actual != expected:
                    error = Refused("signature_outcome")
                    error.outcomes = outcomes
                    raise error
        try:
            identity = backend.identity()
            require(checker_inputs == [{"name": name, "sha256": sha((HERE / name).read_bytes())}
                                      for name in CHECKER_FILES], "checker_changed")
        except Refused as error:
            error.outcomes = outcomes
            raise
        except OSError as error:
            failure = Refused("backend_identity")
            failure.outcomes = outcomes
            raise failure from error
    return {"schema_version": 1, "status": "verified", "source_revision": source_revision,
            "source_revision_is_caller_asserted": True, "node_source": NODE_SOURCE, "backend": identity,
            "checker_inputs": checker_inputs,
            "corpora": corpora, "signed_vectors": len(signed), "signed_account_vectors": 12,
            "signed_momentum_vectors": 79, "unsigned_embedded_account_vectors": 10,
            "unsigned_genesis_momentum_vectors": 1, "intentionally_invalid_amount_vectors_with_valid_signatures": 4,
            "distinct_signed_message_key_pairs": len({(r["message"], r["key"]) for r in signed}),
            "signature_process_outcomes": len(outcomes), "accepted_original_vectors": len(signed),
            "rejected_signature_controls": len(outcomes) - len(signed), "outcomes": outcomes,
            "signature_message": "Python-recomputed SHA3-256 envelope hash, ordinary Ed25519",
            "full_ledger_or_network_trust_validation_performed": False}


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused("arguments")


def emit_report(report, code, pretty=False):
    raw = json.dumps(report, indent=2 if pretty else None, sort_keys=pretty) + "\n"
    try:
        if sys.stdout.write(raw) != len(raw):
            raise OSError("short result write")
        sys.stdout.flush()
    except (OSError, ValueError):
        try:
            sys.stderr.write("node-signatures: cannot write result\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            pass
        return 70
    return code


def discard_failed_output_at_shutdown():
    # Python otherwise retries buffered writes during interpreter shutdown and
    # can replace the controlled exit with 120 or print an I/O traceback.
    # This runs only in the CLI process, after report delivery has failed.
    for stream in (sys.stdout, sys.stderr):
        try:
            descriptor = stream.fileno()
            sink = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(sink, descriptor)
            finally:
                os.close(sink)
        except (OSError, ValueError):
            pass


def main(argv=None):
    parser = QuietParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--openssl", required=True, metavar="EXECUTABLE")
    parser.add_argument("--corpus-dir", type=Path, default=HERE.parents[1] / "internal/testdata/conformance")
    parser.add_argument("--source-revision", metavar="COMMIT")
    try:
        args = parser.parse_args(argv)
        report = run(args.corpus_dir, args.openssl, args.source_revision)
    except Refused as error:
        return emit_report({"schema_version": 1, "status": "refused", "error_stage": error.stage,
                            "signature_process_outcomes": len(error.outcomes), "outcomes": error.outcomes}, 2)
    except (ValueError, KeyError, TypeError, OSError, RecursionError, OverflowError):
        return emit_report({"schema_version": 1, "status": "refused", "error_stage": "corpus_or_backend_input"}, 2)
    return emit_report(report, 0, pretty=True)


if __name__ == "__main__":
    code = main()
    if code == 70:
        discard_failed_output_at_shutdown()
    sys.exit(code)
