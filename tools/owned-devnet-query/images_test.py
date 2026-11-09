# SPDX-License-Identifier: GPL-3.0-only
"""Recipe and image-lifecycle counterexamples; no Docker or Go build is run."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import engine
from engine_test import FixtureRecorder, FixtureResult
import images
import model
import sources

# Exact public Dockerfiles from the contract-selected source revisions. These
# fixtures do not contain a wallet, account seed or executor key.
NODE_RECIPE = b'''# Build Stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache make gcc musl-dev git

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build znnd with the devnet build tag: dev address index 1 is the
# network admin and Settlement's admin delays are shortened. This binary
# is for the local devnet only.
RUN go build -tags devnet -o build/znnd ./cmd/znnd

# Final Stage
FROM alpine:latest

# Install runtime dependencies (if any, like ca-certificates)
RUN apk add --no-cache ca-certificates

# Set working directory
WORKDIR /root

# Create the data directory
RUN mkdir -p /root/.znn

# Copy the binary from the builder stage
COPY --from=builder /app/build/znnd /usr/local/bin/znnd

# Bake committed devnet assets (genesis, per-role configs, pillar keystore + p2p key).
COPY docker/devnet /devnet

# Expose ports:
# 35995: P2P
# 35997: HTTP RPC
# 35998: WS RPC
EXPOSE 35995 35997 35998

# Role-aware entrypoint (picks pillar|rpc via $ZNND_ROLE).
COPY docker/devnet/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
'''
EXECUTOR_RECIPE = b'''FROM golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f AS build
ENV CGO_ENABLED=0
WORKDIR /src/zeno/zeno-executor
COPY --from=go-zenon . /src/zenon-network/go-zenon
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/ ./cmd/...

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS runtime
RUN addgroup -S -g 9999 gateway \\
 && adduser -S -D -H -h /var/lib/gateway -s /sbin/nologin -G gateway -u 9999 gateway \\
 && mkdir -p /var/lib/gateway \\
 && chown 9999:9999 /var/lib/gateway \\
 && chmod 0700 /var/lib/gateway
COPY --from=build /out/ /usr/local/bin/
USER 9999:9999
ENTRYPOINT ["executor"]
'''


class ImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "contract.json")

    def labels(self, role="node"):
        admission = model.admit_engine(self.contract, "fixture-engine", "a" * 32, [], [], [])
        return images.build_labels(self.contract, admission, role, "d" * 64)

    def inspection(self, labels=None):
        return {"Id": "sha256:" + "c" * 64, "Os": "linux", "Architecture": "amd64",
                "Config": {"Labels": labels or self.labels()}, "RepoDigests": []}

    def test_original_recipe_pins_and_only_declared_derivations(self):
        for role, raw in (("node", NODE_RECIPE), ("executor", EXECUTOR_RECIPE)):
            with self.subTest(role=role):
                changed, report = images.recipe(self.contract, role, raw)
                self.assertNotEqual(raw, changed)
                self.assertEqual(report["CGO_ENABLED"], 1 if role == "node" else 0)
                self.assertIn(b"ENV GOMAXPROCS=2 GOFLAGS=-p=2", changed)
                self.assertIn(self.contract.data["images"]["node_build"].encode(), changed)
                self.assertIn(self.contract.data["images"]["runtime"].encode(), changed)
                if role == "node":
                    self.assertIn(b"RUN go build -tags devnet", changed)
                else:
                    self.assertIn(b"ENV CGO_ENABLED=0", changed)
                self.assertEqual(hashlib.sha256(changed).hexdigest(), report["derived"]["sha256"])
                with self.assertRaisesRegex(model.Refused, "build_recipe_source_pin"):
                    images.recipe(self.contract, role, raw + b"\n")

    def test_missing_or_changed_source_recipe_cannot_use_a_known_filename(self):
        for raw in (b"FROM alpine:latest\n", NODE_RECIPE.replace(b"go build", b"go test")):
            with self.assertRaises(model.Refused):
                images.recipe(self.contract, "node", raw)
        with self.assertRaises(model.Refused):
            images.recipe(self.contract, "console", NODE_RECIPE)

    def test_config_digest_iid_and_loaded_image_must_all_match(self):
        value = self.inspection()
        identity = value["Id"]
        self.assertEqual(images.build_result((identity + "\n").encode(),
            {"containerimage.config.digest": identity}, value, self.labels()), identity)
        for iid, metadata, changed in ((b"latest\n", {"containerimage.config.digest": identity}, value),
                ((identity + "\n").encode(), {}, value),
                ((identity + "\n").encode(), {"containerimage.config.digest": "sha256:" + "e" * 64}, value),
                ((identity + "\n").encode(), {"containerimage.config.digest": identity}, {**value, "Id": "sha256:" + "e" * 64})):
            with self.assertRaises(model.Refused):
                images.build_result(iid, metadata, changed, self.labels())

    def test_other_platform_nonce_contract_revision_or_recipe_is_refused(self):
        original = self.inspection()
        for field, wrong in (("Architecture", "arm64"), ("Os", "windows")):
            with self.assertRaises(model.Refused):
                images.require_image({**original, field: wrong}, labels=self.labels())
        for label in self.labels():
            value = deepcopy(original)
            value["Config"]["Labels"][label] = "changed"
            with self.subTest(label=label):
                with self.assertRaises(model.Refused):
                    images.require_image(value, labels=self.labels())

    def test_pull_requires_the_exact_selected_distribution_digest(self):
        reference = self.contract.data["images"]["buildkit"]
        value = self.inspection()
        value["RepoDigests"] = [reference]
        self.assertEqual(images.require_image(value, distribution=reference), value["Id"])
        value["RepoDigests"] = [reference.replace("97719c", "07719c")]
        with self.assertRaisesRegex(model.Refused, "image_distribution_digest"):
            images.require_image(value, distribution=reference)


class ImageRecorder(FixtureRecorder):
    """Synthetic daemon responses and regular result files, with no subprocess."""
    def __init__(self, contract):
        super().__init__(contract)
        self.images = {}
        self.fail_role = None
        self.changed_metadata = False

    def run(self, label, argv, cwd, environment, **options):
        args = argv[1:]
        if args[:2] == ["image", "pull"]:
            value = {"Id": "sha256:" + "c" * 64, "Os": "linux", "Architecture": "amd64",
                     "Config": {"Labels": {}}, "RepoDigests": [args[-1]]}
            self.images[args[-1]] = value
            raw = b"synthetic pull response\n"
        elif args[:2] == ["image", "inspect"]:
            raw = model.canonical(self.images[args[-1]])
        elif args[:2] == ["buildx", "version"]:
            raw = b"synthetic buildx version; not executed\n"
        elif args[:2] == ["buildx", "create"]:
            self.assert_remote = args[args.index("--driver") + 1] == "remote" and args[-1] == "tcp://127.0.0.1:12340"
            assert self.assert_remote
            raw = (args[args.index("--name") + 1] + "\n").encode()
        elif args[:2] == ["buildx", "inspect"]:
            raw = b"synthetic ready response\n"
        elif args[:2] == ["buildx", "build"]:
            role = "node" if Path(args[-1]).name == "node" else "executor"
            if role == self.fail_role:
                raise model.Refused("synthetic_build_failure")
            labels = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "--label")
            identity = "sha256:" + ("1" if role == "node" else "2") * 64
            self.images[identity] = {"Id": identity, "Os": "linux", "Architecture": "amd64",
                "Config": {"Labels": labels}, "RepoDigests": []}
            Path(args[args.index("--iidfile") + 1]).write_bytes((identity + "\n").encode("ascii"))
            Path(args[args.index("--metadata-file") + 1]).write_bytes(model.canonical(
                {"containerimage.config.digest": "sha256:" + "f" * 64 if self.changed_metadata else identity}))
            raw = b"synthetic build response\n"
        else:
            return super().run(label, argv, cwd, environment, **options)
        if options.get("guard"):
            options["guard"]()
        self.calls.append(args)
        return FixtureResult(raw)


class BuildLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "contract.json")

    def prepare(self, root):
        recorder = ImageRecorder(self.contract)
        client = engine.Engine(self.contract, model.ExecutionIdentity("e" * 40, 1, 1, "edgepillar"),
            recorder, root / "engine", ["fixture-docker"], {"PATH": "/fixture/bin"}, lambda: None)
        with mock.patch.object(engine.platform, "system", return_value="Linux"), \
             mock.patch.object(engine.platform, "machine", return_value="x86_64"):
            client.probe()
        rows = []
        for role in sources.ROLES:
            path = root / role
            path.mkdir()
            if role in images.RECIPES:
                target = path / images.RECIPES[role]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(NODE_RECIPE if role == "node" else EXECUTOR_RECIPE)
            selected = self.contract.data["sources"][role]
            # Empty tracked sets isolate build orchestration. Source-checkout
            # validation is qualified separately, not by this response fixture.
            rows.append(sources.Checkout(role, path, sources._directory_identity(path),
                selected["repository"], selected["revision"], "f" * 40, (), (), b"[]"))
        return client, recorder, images.Builder(self.contract, client, sources.PreparedSources(tuple(rows)), root / "images")

    def test_two_shared_builds_close_builder_before_any_runtime_image_is_returned(self):
        with tempfile.TemporaryDirectory(prefix="image-regular-control-") as temporary:
            client, recorder, builder = self.prepare(Path(temporary))
            prepared = builder.prepare()
            self.assertTrue(client.builder_closed)
            self.assertEqual(recorder.containers, {})
            builds = [call for call in recorder.calls if call[:2] == ["buildx", "build"]]
            self.assertEqual(len(builds), 2)
            self.assertNotIn("--build-context", builds[0])
            self.assertIn("--build-context", builds[1])
            for call in builds:
                self.assertIn("--load", call)
                self.assertNotIn("--push", call)
                self.assertNotIn("--cache-to", call)
            self.assertEqual(prepared.image_for("pillar"), prepared.image_for("rpc"))
            self.assertEqual(prepared.image_for("executor"), prepared.image_for("gateway"))
            self.assertFalse(any(call[:2] in (["image", "save"], ["image", "rm"], ["volume", "rm"])
                                 or "prune" in call for call in recorder.calls))
            with self.assertRaisesRegex(model.Refused, "image_build_already_attempted"):
                builder.prepare()

    def test_incomplete_build_keeps_the_builder_id_for_scoped_cleanup_and_never_retries(self):
        with tempfile.TemporaryDirectory(prefix="image-regular-control-") as temporary:
            client, recorder, builder = self.prepare(Path(temporary))
            recorder.fail_role = "executor"
            with self.assertRaisesRegex(model.Refused, "synthetic_build_failure"):
                builder.prepare()
            self.assertFalse(client.builder_closed)
            self.assertEqual(set(client.owned), {"buildkit"})
            client.cleanup()
            self.assertTrue(all(not row["State"]["Running"] for row in recorder.containers.values()))
            with self.assertRaisesRegex(model.Refused, "image_build_already_attempted"):
                builder.prepare()

    def test_mismatched_build_metadata_cannot_return_a_runtime_image(self):
        with tempfile.TemporaryDirectory(prefix="image-regular-control-") as temporary:
            client, recorder, builder = self.prepare(Path(temporary))
            recorder.changed_metadata = True
            with self.assertRaisesRegex(model.Refused, "build_metadata_config_digest"):
                builder.prepare()
            self.assertNotIn("image-preparation.json", recorder.seals)
            client.cleanup()

    def test_a_replaced_built_image_is_refused_at_runtime_selection(self):
        with tempfile.TemporaryDirectory(prefix="image-regular-control-") as temporary:
            client, recorder, builder = self.prepare(Path(temporary))
            prepared = builder.prepare()
            identity = prepared.values["node"]["id"]
            recorder.images[identity]["Config"]["Labels"][images.SOURCE_LABEL] = "e" * 40
            with self.assertRaisesRegex(model.Refused, "image_build_binding"):
                prepared.image_for("rpc")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None:
        model.digest(args.source_revision, model.HEX40)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    sys.stdout.buffer.write(model.canonical({"format": "owned-devnet-image-controls/v1",
        "source_revision": args.source_revision, "root_tests": result.testsRun,
        "errors": len(result.errors), "failures": len(result.failures), "skipped": len(result.skipped),
        "successful": result.wasSuccessful(), "scope": "SOURCE_RECIPE_AND_SYNTHETIC_BUILD_RESPONSES",
        "docker_contacted_or_image_built_or_service_started": False}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
