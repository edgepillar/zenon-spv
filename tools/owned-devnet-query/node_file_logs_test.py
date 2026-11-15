# SPDX-License-Identifier: GPL-3.0-only
"""Regular-file and in-memory controls for private node log-file observations."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import model
import node_diagnostics as nodes
import node_diagnostics_test as fixtures
import node_file_logs as files
import process


def tar_entries(entries, *, pax=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, raw, kind in entries:
            entry = tarfile.TarInfo(name);entry.type = kind
            entry.size = len(raw) if kind == tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):entry.linkname = "private-marker"
            entry.pax_headers = pax or {}
            archive.addfile(entry, io.BytesIO(raw) if entry.size else None)
    return buffer.getvalue()


class ArchiveTests(unittest.TestCase):
    def test_independently_encoded_ustar_entry_excludes_raw_text(self):
        payload = b'msg="failed to generate momentum" reason="private-marker"\n'
        header = bytearray(512);header[:9] = b"zenon.log"
        for start, stop, value in ((100, 108, b"0000600\0"), (108, 116, b"0000000\0"),
                                  (116, 124, b"0000000\0"), (136, 148, b"00000000000\0")):
            header[start:stop] = value
        header[124:136] = (f"{len(payload):011o}\0").encode();header[148:156] = b"        "
        header[156:157] = b"0";header[257:263] = b"ustar\0";header[263:265] = b"00"
        header[148:156] = (f"{sum(header):06o}\0 ").encode()
        raw = bytes(header) + payload + b"\0" * ((-len(payload)) % 512 + 1024)
        row = files.archive_summary(raw, "run");files.check_data(row)
        self.assertEqual(row["content"], {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        self.assertEqual(row["log"]["events"]["generation_failed"], 1)
        self.assertNotIn("private-marker", json.dumps(row))

    def test_both_fixed_names_and_empty_file_are_supported(self):
        for kind, path in files.FILES:
            with self.subTest(kind=kind):
                row = files.archive_summary(tar_entries([(path.rsplit("/", 1)[-1], b"", tarfile.REGTYPE)]), kind)
                files.check_data(row);self.assertEqual(row["content"]["bytes"], 0)

    def test_bounded_pax_timestamps_do_not_become_report_fields(self):
        raw = tar_entries([("zenon.log", b"entry\n", tarfile.REGTYPE)], pax={"mtime": "1700000000.123456789"})
        row = files.archive_summary(raw, "run");files.check_data(row)
        self.assertNotIn("1700000000", json.dumps(row))

    def test_archive_bounds_truncation_encoding_and_trailing_bytes_refuse(self):
        raw = fixtures.file_archive()
        for candidate in (b"", b"not a tar", raw[:-1], raw[:-10240], b"x" * (files.ARCHIVE_BYTES + 512),
                          raw + b"x" * 512):
            with self.subTest(length=len(candidate)), self.assertRaises(model.Refused):
                files.archive_summary(candidate, "run")
        for kind in ("other", [], True):
            with self.assertRaises(model.Refused):files.archive_summary(raw, kind)
        # A tiny in-memory archive must not authorize a huge seek or metadata read.
        for entry_type in (tarfile.REGTYPE, tarfile.XHDTYPE):
            oversized = bytearray(raw)
            oversized[124:136] = b"\x80" + b"\xff" * 11
            oversized[156:157] = entry_type
            oversized[148:156] = b"        "
            oversized[148:156] = (f"{sum(oversized[:512]):06o}\0 ").encode()
            with self.subTest(entry_type=entry_type), self.assertRaises(model.Refused):
                files.archive_summary(bytes(oversized), "run")

    def test_one_exact_regular_file_is_required(self):
        for entries in ([('other.log', b'x', tarfile.REGTYPE)],
                        [('../zenon.log', b'x', tarfile.REGTYPE)],
                        [('zenon.log', b'x', tarfile.REGTYPE), ('extra', b'x', tarfile.REGTYPE)],
                        [('zenon.log', b'', tarfile.SYMTYPE)], [('zenon.log', b'', tarfile.LNKTYPE)],
                        [('zenon.log', b'', tarfile.FIFOTYPE)], [('zenon.log', b'', tarfile.DIRTYPE)]):
            with self.subTest(entries=entries), self.assertRaises(model.Refused):
                files.archive_summary(tar_entries(entries), "run")

    def test_payload_line_and_metadata_limits_remain_explicit(self):
        for payload in (b'x' * (nodes.LOG_BYTES + 1), b'x\n' * (nodes.MAX_LINES + 1)):
            with self.assertRaises(model.Refused):
                files.archive_summary(tar_entries([('zenon.log', payload, tarfile.REGTYPE)]), "run")
        raw = tar_entries([('zenon.log', b'entry', tarfile.REGTYPE)], pax={'comment': 'private-marker'})
        with self.assertRaises(model.Refused):files.archive_summary(raw, "run")

    def test_decoded_data_is_only_a_pin_and_allowlisted_summary(self):
        base = files.archive_summary(fixtures.file_archive(), "run")
        for key, value in (("content", {"bytes": True, "sha256": "f" * 64}),
                           ("log", {"raw": "private-marker"}), ("raw", "private-marker")):
            row = deepcopy(base);row[key] = value
            with self.assertRaises(model.Refused):files.check_data(row)

    def test_fixed_error_codes_and_escaped_source_locations_exclude_private_values(self):
        payload = (b'msg="vm panic when applying momentum" reason="private-marker" '
                   b'stack="goroutine private-marker\\n\\t/app/vm/supervisor.go:198 +0xab\\n'
                   b'\\t/foreign/private-marker.go:12 +0xab"\n'
                   b'msg="failed to generate momentum" reason="supervisor - VM panic"\n')
        row = files.archive_summary(fixtures.file_archive(payload=payload), 'run');files.check_data(row)
        self.assertEqual(row['classification']['events']['vm_panic'], 1)
        self.assertEqual(row['classification']['reasons']['vm_panic'], 1)
        self.assertEqual(row['classification']['source_locations'], [{'file': 'vm/supervisor.go', 'line': 198}])
        self.assertNotIn('private-marker', json.dumps(row))

    def test_reason_values_match_complete_source_constants_without_exporting_unknown_text(self):
        payload = (b'reason="momentum version is invalid"\n'
                   b'reason="momentum version is invalid private-marker"\n'
                   b'reason="unknown private-marker"\n')
        row = files.archive_summary(fixtures.file_archive(payload=payload), 'run');files.check_data(row)
        self.assertEqual(row['classification']['reasons']['momentum_version'], 1)
        self.assertNotIn('private-marker', json.dumps(row))

    def test_classification_rejects_private_paths_boolean_counts_and_duplicate_locations(self):
        base = files.archive_summary(fixtures.file_archive(), 'run')
        for change in ('path', 'boolean', 'duplicate', 'extra'):
            row = deepcopy(base)
            if change == 'path':row['classification']['source_locations'] = [{'file': '../private.go', 'line': 1}]
            elif change == 'boolean':row['classification']['events']['vm_panic'] = True
            elif change == 'duplicate':row['classification']['source_locations'] = [{'file': 'vm/supervisor.go', 'line': 1}] * 2
            else:row['classification']['raw'] = 'private-marker'
            with self.subTest(change=change), self.assertRaises(model.Refused):files.check_data(row)


class CaptureTests(unittest.TestCase):
    def prepare(self, root):
        return fixtures.StartupNodeCaptureTests().prepare(root)

    def test_all_reads_have_exact_owned_source_and_stdout_destination(self):
        with tempfile.TemporaryDirectory(prefix="file-logs-regular-capture-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            with mock.patch.object(client, "_run", side_effect=run):client.capture_startup_diagnostics()
            reads = [c for c in calls if c[1][:2] in (["container", "exec"], ["container", "cp"])]
            self.assertEqual(len(calls), 17);self.assertEqual(len(reads), 8)
            expected = [(["container", "exec", client.owned[role].identity, "/bin/busybox", "tail", "-c",
                          str(files.TAIL_BYTES), "--", path] if kind == "run" else
                         ["container", "cp", client.owned[role].identity + ":" + path, "-"])
                        for role in nodes.ROLES for kind, path in files.FILES]
            self.assertEqual([c[1] for c in reads], expected)
            self.assertTrue(all(c[2] == {
                "timeout": 5, "stdout_cap": files.TAIL_BYTES if c[1][1] == "exec" else files.ARCHIVE_BYTES,
                "stderr_cap": 4096} for c in reads))
            row = json.loads(recorder.seals[files.REPORT]);self.assertEqual(row["status"], "OBSERVED")
            self.assertNotIn("private-marker", json.dumps(row))

    def test_failed_optional_file_retains_actual_exit_without_parsed_data(self):
        with tempfile.TemporaryDirectory(prefix="file-logs-regular-failure-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            def failed(label, arguments, **options):
                if label == "startup-file-pillar-error":
                    client.counter += 1
                    raise process.CommandFailed(fixtures.MemoryResult(f"docker-{client.counter:03d}-{label}", b"", b"private-marker", actual_exit=1))
                return run(label, arguments, **options)
            with mock.patch.object(client, "_run", side_effect=failed):client.capture_startup_diagnostics()
            row = json.loads(recorder.seals[files.REPORT]);phase = row["nodes"][0]["files"][1]["phase"]
            self.assertEqual((phase["status"], phase["actual_exit"]), ("FAILURE", 1))
            self.assertIsNone(phase["data"]);self.assertEqual(row["status"], "UNKNOWN")
            self.assertNotIn("private-marker", json.dumps(row))

    def test_unowned_image_cannot_select_a_log_file_read(self):
        with tempfile.TemporaryDirectory(prefix="file-logs-regular-image-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            client.expected_images['pillar'] = 'sha256:' + 'f' * 64
            with mock.patch.object(client, "_run", side_effect=run):client.capture_startup_diagnostics()
            self.assertFalse(any(c[0].startswith('startup-file-pillar-') for c in calls))
            row = json.loads(recorder.seals[files.REPORT])
            self.assertTrue(all(item['phase'] == nodes.empty_phase() for item in row['nodes'][0]['files']))

    def test_interruption_keeps_file_capture_unknown_and_base_observation(self):
        with tempfile.TemporaryDirectory(prefix="file-logs-regular-interruption-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            def interrupted(label, arguments, **options):
                if label == 'startup-file-pillar-run':raise KeyboardInterrupt
                return run(label, arguments, **options)
            with mock.patch.object(client, '_run', side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
                client.capture_startup_diagnostics()
            row = json.loads(recorder.seals[files.REPORT])
            self.assertEqual((row['status'], row['reason']), ('UNKNOWN', 'capture_interrupted'))
            self.assertEqual(json.loads(recorder.seals[nodes.REPORT])['status'], 'OBSERVED')

    def test_fresh_file_budget_refusal_keeps_unlaunched_fields_empty(self):
        with tempfile.TemporaryDirectory(prefix="file-logs-regular-budget-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            def guard():
                if calls and calls[-1][0].startswith('startup-file-'):raise model.Refused('unit_budget')
            client.guard = guard
            with mock.patch.object(client, '_run', side_effect=run):client.capture_startup_diagnostics()
            row = json.loads(recorder.seals[files.REPORT])
            for node in row['nodes']:
                for item in node['files']:
                    phase = item['phase'];self.assertEqual(phase['status'], 'REFUSED')
                    self.assertTrue(all(phase[k] is None for k in ('command', 'actual_exit', 'output_complete', 'outputs', 'data')))
            self.assertEqual(row['status'], 'UNKNOWN')

    def test_incomplete_file_command_cannot_supply_parsed_log_events(self):
        with tempfile.TemporaryDirectory(prefix="file-logs-regular-incomplete-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            def incomplete(label, arguments, **options):
                if label == 'startup-file-pillar-error':
                    client.counter += 1
                    raise process.CommandFailed(fixtures.MemoryResult(f'docker-{client.counter:03d}-{label}',
                        fixtures.file_archive('error'), actual_exit=-15, complete=False, reason='timeout'))
                return run(label, arguments, **options)
            with mock.patch.object(client, '_run', side_effect=incomplete):client.capture_startup_diagnostics()
            phase = json.loads(recorder.seals[files.REPORT])['nodes'][0]['files'][1]['phase']
            self.assertEqual((phase['status'], phase['reason']), ('UNKNOWN', 'command_incomplete'))
            self.assertEqual(phase['actual_exit'], -15);self.assertFalse(phase['output_complete'])
            self.assertIsNone(phase['data'])


class ReviewTests(unittest.TestCase):
    def payload(self, kind):
        return fixtures.file_archive(kind)

    def data(self, raw, kind):
        return files.archive_summary(raw, kind)

    def fixture(self):
        contract, entries, startup = fixtures.StartupNodeArchiveTests().files()
        counter = 50
        report = {"format": "owned-devnet-startup-file-logs/v1", "trigger": "owned_rpc_readiness_deadline",
            "status": "OBSERVED", "reason": None, "observed_before_cleanup": True, "atomic_snapshot": False,
            "accepted_header_authority": False, "production_qualified": False, "raw_logs_exported": False, "nodes": []}
        for node in startup['nodes']:
            row = {'service': node['service'], 'inspection_command': node['inspection']['command'], 'files': []}
            for kind, _ in files.FILES:
                label = f'docker-{counter:03d}-startup-file-{node["service"]}-{kind}';counter += 1
                raw = self.payload(kind)
                result = fixtures.MemoryResult(label, raw)
                phase = nodes.empty_phase();nodes.complete_command(phase, result)
                phase.update(status='OBSERVED', reason=None, data=self.data(raw, kind))
                entries['evidence/' + label + '.complete.json'] = model.canonical(result.receipt)
                entries['evidence/' + label + '.started.json'] = model.canonical({
                    'format': 'owned-devnet-command-started/v1', 'label': label,
                    'pid': 42, 'process_group': 42, 'new_session_requested': True})
                row['files'].append({'kind': kind, 'phase': phase})
            report['nodes'].append(row)
        entries['evidence/' + files.REPORT] = model.canonical(report)
        return contract, entries, report

    def review(self, contract, entries, report):
        entries['evidence/' + files.REPORT] = model.canonical(report)
        return fixtures.StartupNodeArchiveTests().review(contract, entries)

    def test_summary_is_nonaccepting_and_does_not_replay_excluded_tar_or_text(self):
        contract, entries, report = self.fixture();row = self.review(contract, entries, report)
        observed = row['startup_file_log_diagnostics']
        self.assertTrue(observed['diagnostic_assertions_only'])
        self.assertFalse(observed['original_tar_or_text_independently_rechecked'])
        self.assertFalse(observed['accepted_header_authority'])
        self.assertIsNone(row['comparison']);self.assertEqual(row['recorded_terminal_outcome'], 'REFUSED')
        self.assertNotIn('private-marker', json.dumps(observed))

    def test_legacy_result_without_file_capture_keeps_its_shape(self):
        contract, entries, _ = fixtures.StartupNodeArchiveTests().files()
        row = fixtures.StartupNodeArchiveTests().review(contract, entries)
        self.assertNotIn('startup_file_log_diagnostics', row)

    def test_scope_authority_and_unknown_fields_refuse(self):
        for key, value in (('raw_logs_exported', True), ('accepted_header_authority', True),
                           ('production_qualified', True), ('atomic_snapshot', True),
                           ('observed_before_cleanup', False), ('format', 'other/v1'), ('extra', 'private-marker')):
            contract, entries, report = self.fixture();report[key] = value
            with self.subTest(key=key), self.assertRaises(model.Refused):self.review(contract, entries, report)

    def test_inspection_kind_and_command_receipts_are_bound(self):
        for change in ('inspection', 'kind', 'exit', 'complete', 'digest', 'start', 'command', 'missing_stream'):
            contract, entries, report = self.fixture();node = report['nodes'][0];item = node['files'][0]
            phase = item['phase'];label = phase['command']
            if change == 'inspection':node['inspection_command'] = 'docker-001-other'
            elif change == 'kind':item['kind'] = 'other'
            elif change == 'exit':phase['actual_exit'] = True
            elif change == 'complete':phase['output_complete'] = False
            elif change == 'digest':phase['outputs']['stdout']['sha256'] = 'f' * 64
            elif change == 'start':del entries['evidence/' + label + '.started.json']
            elif change == 'command':phase['command'] = 'docker-050-startup-file-rpc-error'
            else:
                receipt = json.loads(entries['evidence/' + label + '.complete.json']);del receipt['outputs']['stderr']
                entries['evidence/' + label + '.complete.json'] = model.canonical(receipt)
            with self.subTest(change=change), self.assertRaises(model.Refused):self.review(contract, entries, report)

    def test_missing_file_preserves_failure_and_refuses_fabricated_data(self):
        contract, entries, report = self.fixture();phase = report['nodes'][0]['files'][1]['phase'];label = phase['command']
        phase.update(status='FAILURE', reason='command_failed', actual_exit=1, data=None)
        receipt = json.loads(entries['evidence/' + label + '.complete.json']);receipt['actual_exit'] = 1
        entries['evidence/' + label + '.complete.json'] = model.canonical(receipt)
        report.update(status='UNKNOWN', reason='incomplete_diagnostics')
        row = self.review(contract, entries, report)['startup_file_log_diagnostics']['summary']
        self.assertEqual(row['nodes'][0]['files'][1]['phase']['actual_exit'], 1)
        phase['data'] = files.archive_summary(fixtures.file_archive('error'), 'error')
        with self.assertRaises(model.Refused):self.review(contract, entries, report)

    def test_capture_requires_prior_node_summary_and_its_original_inspection(self):
        contract, entries, report = self.fixture()
        del entries['evidence/' + nodes.REPORT]
        with self.assertRaises(model.Refused):self.review(contract, entries, report)

    def test_cleanup_order_and_orphan_records_are_refused(self):
        contract, entries, report = self.fixture()
        phase = report['nodes'][0]['files'][0]['phase'];old = phase['command'];label = 'docker-048-startup-file-pillar-run'
        result = fixtures.MemoryResult(label, self.payload('run'));nodes.complete_command(phase, result)
        del entries['evidence/' + old + '.complete.json'];del entries['evidence/' + old + '.started.json']
        entries['evidence/' + label + '.complete.json'] = model.canonical(result.receipt)
        entries['evidence/' + label + '.started.json'] = model.canonical({'format': 'owned-devnet-command-started/v1',
            'label': label, 'pid': 42, 'process_group': 42, 'new_session_requested': True})
        with self.assertRaisesRegex(model.Refused, 'review_file_log_order'):self.review(contract, entries, report)
        contract, entries, report = self.fixture()
        entries['evidence/docker-051-stop-rpc.started.json'] = model.canonical({'scope': 'control'})
        with self.assertRaisesRegex(model.Refused, 'review_file_log_cleanup_order'):
            self.review(contract, entries, report)
        del entries['evidence/docker-051-stop-rpc.started.json'];del entries['evidence/' + files.REPORT]
        with self.assertRaisesRegex(model.Refused, 'review_file_log_summary_missing'):
            fixtures.StartupNodeArchiveTests().review(contract, entries)

    def test_raw_tar_or_stderr_cannot_enter_the_public_index(self):
        for suffix in ('.stdout', '.stderr'):
            contract, entries, report = self.fixture();label = report['nodes'][0]['files'][0]['phase']['command']
            entries['evidence/' + label + suffix] = b'private-marker'
            with self.assertRaisesRegex(model.Refused, 'review_member_selection'):
                self.review(contract, entries, report)


class TailTests(unittest.TestCase):
    def test_complete_inner_record_has_independent_pin_and_late_code(self):
        leading, record, trailing = (b'fragment\n',
            b'msg="do not broadcast own momentum" reason=too-late\n', b'partial')
        raw = leading + record + trailing
        row = files.tail_summary(raw);files.check_data(row, tail=True)
        self.assertEqual(row['content'], {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        self.assertEqual(row['window'], {'scope': 'bounded-complete-lines', 'whole_file_coverage': False,
            'leading_discarded_bytes': len(leading), 'trailing_discarded_bytes': len(trailing),
            'classified_bytes': len(record)})
        self.assertEqual(row['log']['events']['late_broadcast'], 1)
        self.assertEqual(row['classification']['reasons']['late_production'], 1)

    def test_empty_single_record_and_unterminated_windows_have_no_complete_inner_records(self):
        for raw in (b'', b'one record\n', b'unterminated', b'\n'):
            row = files.tail_summary(raw);files.check_data(row, tail=True)
            self.assertEqual(row['log']['total_lines'], 0)
            self.assertFalse(row['window']['whole_file_coverage'])

    def test_large_log_supplies_only_the_bounded_recent_window(self):
        source = (b'x' * 199 + b'\n') * 8192 + b'msg="do not broadcast own momentum" reason=too-late\n'
        raw = source[-files.TAIL_BYTES:]
        self.assertGreater(len(source), files.ARCHIVE_BYTES)
        row = files.tail_summary(raw);files.check_data(row, tail=True)
        self.assertEqual(row['content']['bytes'], files.TAIL_BYTES)
        self.assertEqual(row['classification']['reasons']['late_production'], 1)
        self.assertLessEqual(row['log']['total_lines'], nodes.MAX_LINES)

    def test_byte_bound_and_types_are_checked_before_classification(self):
        for raw in (b'x' * (files.TAIL_BYTES + 1), 'text', True, None):
            with self.assertRaises(model.Refused):files.tail_summary(raw)

    def test_invalid_inner_utf8_remains_private_and_explicit(self):
        raw = b'private-marker\n\xff private-marker\n'
        row = files.tail_summary(raw);files.check_data(row, tail=True)
        self.assertTrue(row['log']['invalid_utf8'])
        self.assertNotIn('private-marker', json.dumps(row))

    def test_possible_leading_and_trailing_fragments_are_not_classified(self):
        event = b'msg="do not broadcast own momentum" reason=too-late'
        row = files.tail_summary(event + b'\nordinary\n' + event)
        files.check_data(row, tail=True)
        self.assertEqual(row['log']['events']['late_broadcast'], 0)
        self.assertEqual(row['classification']['reasons']['late_production'], 0)
        self.assertEqual(row['log']['total_lines'], 1)

    def test_line_bound_is_not_removed_for_byte_tails(self):
        with self.assertRaises(model.Refused):files.tail_summary(b'line\n' * (nodes.MAX_LINES + 2))

    def test_tail_data_cannot_be_silently_read_as_a_whole_file_v1_summary(self):
        row = files.tail_summary(fixtures.file_tail())
        with self.assertRaises(model.Refused):files.check_data(row)


class TailReviewTests(ReviewTests):
    def payload(self, kind):
        return fixtures.file_tail()

    def data(self, raw, kind):
        return files.tail_summary(raw)

    def fixture(self):
        contract, entries, report = super().fixture()
        report['format'] = 'owned-devnet-startup-file-logs/v2'
        entries['evidence/' + files.REPORT] = model.canonical(report)
        return contract, entries, report

    def test_tail_pin_is_the_exact_command_stdout_pin(self):
        contract, entries, report = self.fixture()
        report['nodes'][0]['files'][0]['phase']['data']['content']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(model.Refused, 'review_file_log_tail_pin'):
            self.review(contract, entries, report)

    def test_window_scope_accounting_types_and_unknown_fields_refuse(self):
        for change in ('coverage', 'count', 'boolean', 'extra'):
            contract, entries, report = self.fixture();window = report['nodes'][0]['files'][0]['phase']['data']['window']
            if change == 'coverage':window['whole_file_coverage'] = True
            elif change == 'count':window['classified_bytes'] += 1
            elif change == 'boolean':window['leading_discarded_bytes'] = True
            else:window['raw'] = 'private-marker'
            with self.subTest(change=change), self.assertRaises(model.Refused):
                self.review(contract, entries, report)

    def test_tail_stdout_cannot_inherit_the_larger_legacy_tar_cap(self):
        contract, entries, report = self.fixture();phase = report['nodes'][0]['files'][0]['phase']
        phase['outputs']['stdout']['bytes'] = files.TAIL_BYTES + 1
        path = 'evidence/' + phase['command'] + '.complete.json'
        receipt = json.loads(entries[path]);receipt['outputs']['stdout']['bytes'] = files.TAIL_BYTES + 1
        entries[path] = model.canonical(receipt)
        with self.assertRaises(model.Refused):self.review(contract, entries, report)

    def test_legacy_format_cannot_relabel_tail_data(self):
        contract, entries, report = self.fixture();report['format'] = 'owned-devnet-startup-file-logs/v1'
        with self.assertRaises(model.Refused):self.review(contract, entries, report)


class MethodTests(unittest.TestCase):
    def state(self, **changes):
        values = dict(Running=True, Paused=False, Restarting=False, Dead=False)
        values.update(changes)
        return fixtures.engine.stop_state_summary({'State': values})

    def test_exec_requires_all_four_positive_state_observations(self):
        self.assertEqual(files.read_method(self.state()), 'byte-tail')
        for key, value in (('Running', False), ('Paused', True), ('Restarting', True), ('Dead', True)):
            with self.subTest(key=key):
                self.assertEqual(files.read_method(self.state(**{key: value})), 'whole-file')
        for key in ('Running', 'Paused', 'Restarting', 'Dead'):
            row = self.state();del row['fields'][key]
            row['unavailable_fields'] = sorted(set(row['unavailable_fields']) | {key})
            self.assertEqual(files.read_method(row), 'whole-file')

    def test_method_selection_does_not_coerce_a_boolean(self):
        row = self.state();row['fields']['Running'] = 1
        with self.assertRaises(model.Refused):files.read_method(row)


class StateCaptureTests(unittest.TestCase):
    def prepare(self, root):
        return fixtures.StartupNodeCaptureTests().prepare(root)

    def test_stopped_node_uses_only_two_bounded_stdout_archives(self):
        with tempfile.TemporaryDirectory(prefix='stopped-file-regular-') as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            recorder.containers[client.owned['pillar3'].identity]['State'].update(
                Running=False, Pid=0, ExitCode=2, Status='exited')
            with mock.patch.object(client, '_run', side_effect=run):client.capture_startup_diagnostics()
            copies = [c for c in calls if c[1][:2] == ['container', 'cp']]
            tails = [c for c in calls if c[1][:2] == ['container', 'exec']]
            self.assertEqual((len(calls), len(copies), len(tails)), (17, 5, 3))
            self.assertEqual([c[1] for c in copies if c[1][2].startswith(client.owned['pillar3'].identity + ':')], [
                ['container', 'cp', client.owned['pillar3'].identity + ':' + path, '-']
                for _, path in files.FILES])
            self.assertTrue(all(c[2] == {'timeout': 5, 'stdout_cap': files.ARCHIVE_BYTES,
                                       'stderr_cap': 4096} for c in copies))
            report = json.loads(recorder.seals[files.REPORT])
            self.assertEqual(report['format'], 'owned-devnet-startup-file-logs/v4')
            row = report['nodes'][2]
            self.assertTrue(all(x['method'] == 'whole-file' and x['phase']['status'] == 'OBSERVED'
                                and 'window' not in x['phase']['data'] for x in row['files']))
            self.assertFalse(report['accepted_header_authority'])

    def test_paused_node_is_read_without_resuming_or_starting_it(self):
        with tempfile.TemporaryDirectory(prefix='paused-file-regular-') as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            recorder.containers[client.owned['rpc'].identity]['State'].update(Paused=True, Status='paused')
            with mock.patch.object(client, '_run', side_effect=run):client.capture_startup_diagnostics()
            self.assertEqual(len(calls), 17)
            copies = [c for c in calls if c[1][:2] == ['container', 'cp']]
            self.assertEqual(len(copies), 5)
            self.assertEqual(sum(c[1][2].startswith(client.owned['rpc'].identity + ':') for c in copies), 2)
            self.assertTrue(all(c[1][:2] not in (['container', 'start'], ['container', 'unpause']) for c in calls))

    def test_exit_after_inspection_keeps_failure_without_a_second_read(self):
        with tempfile.TemporaryDirectory(prefix='changed-file-state-regular-') as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            def changed(label, arguments, **options):
                if arguments[:2] == ['container', 'exec'] and arguments[2] == client.owned['pillar3'].identity:
                    calls.append((label, arguments, options));client.counter += 1
                    raise process.CommandFailed(fixtures.MemoryResult(
                        f'docker-{client.counter:03d}-{label}', b'', b'private-marker', actual_exit=1))
                return run(label, arguments, **options)
            with mock.patch.object(client, '_run', side_effect=changed):client.capture_startup_diagnostics()
            self.assertEqual(len(calls), 17)
            copies = [c for c in calls if c[1][:2] == ['container', 'cp']]
            self.assertEqual(len(copies), 4)
            self.assertTrue(all(c[1][2].endswith(dict(files.FILES)['error']) for c in copies))
            report = json.loads(recorder.seals[files.REPORT])
            self.assertEqual(report['status'], 'UNKNOWN')
            run_file, error_file = report['nodes'][2]['files']
            self.assertEqual((run_file['method'], run_file['phase']['status']), ('byte-tail', 'FAILURE'))
            self.assertIsNone(run_file['phase']['data'])
            self.assertEqual((error_file['method'], error_file['phase']['status']), ('whole-file', 'OBSERVED'))
            self.assertNotIn('private-marker', json.dumps(report))


class MixedReviewTests(TailReviewTests):
    def fixture(self):
        contract, entries, report = super().fixture()
        startup = json.loads(entries['evidence/' + nodes.REPORT])
        report['format'] = 'owned-devnet-startup-file-logs/v3'
        for original, row in zip(startup['nodes'], report['nodes']):
            fields = original['inspection']['data']['fields']
            fields.update(Paused=False, Restarting=False, Dead=False)
            original['inspection']['data'] = fixtures.engine.stop_state_summary({'State': {**fields, 'Error': ''}})
            method = 'whole-file' if row['service'] == 'pillar3' else 'byte-tail'
            for item in row['files']:
                item['method'] = method;phase = item['phase'];label = phase['command']
                raw = fixtures.file_archive(item['kind']) if method == 'whole-file' else fixtures.file_tail()
                result = fixtures.MemoryResult(label, raw);nodes.complete_command(phase, result)
                phase['data'] = (files.archive_summary(raw, item['kind']) if method == 'whole-file'
                                 else files.tail_summary(raw))
                entries['evidence/' + label + '.complete.json'] = model.canonical(result.receipt)
        entries['evidence/' + nodes.REPORT] = model.canonical(startup)
        entries['evidence/' + files.REPORT] = model.canonical(report)
        return contract, entries, report

    def test_both_methods_keep_their_own_data_schema_and_no_authority(self):
        contract, entries, report = self.fixture()
        summary = self.review(contract, entries, report)['startup_file_log_diagnostics']['summary']
        self.assertFalse(summary['accepted_header_authority'])
        for row in summary['nodes']:
            for item in row['files']:
                self.assertEqual(item['method'], 'whole-file' if row['service'] == 'pillar3' else 'byte-tail')
                self.assertEqual('window' in item['phase']['data'], item['method'] == 'byte-tail')

    def test_method_must_match_the_prior_inspection(self):
        for value in ('whole-file', 'private-marker', True, None):
            contract, entries, report = self.fixture();report['nodes'][0]['files'][0]['method'] = value
            with self.subTest(value=value), self.assertRaisesRegex(model.Refused, 'review_file_log_method_binding'):
                self.review(contract, entries, report)

    def test_modified_prior_running_state_cannot_relabel_an_archive(self):
        contract, entries, report = self.fixture()
        startup = json.loads(entries['evidence/' + nodes.REPORT])
        startup['nodes'][2]['inspection']['data']['fields']['Running'] = True
        entries['evidence/' + nodes.REPORT] = model.canonical(startup)
        with self.assertRaisesRegex(model.Refused, 'review_file_log_method_binding'):
            self.review(contract, entries, report)

    def test_archive_keeps_its_larger_transport_cap_and_small_decoded_file(self):
        contract, entries, report = self.fixture();item = report['nodes'][2]['files'][0]
        phase = item['phase'];label = phase['command']
        raw = fixtures.file_archive('run', b'x' * files.TAIL_BYTES)
        self.assertGreater(len(raw), files.TAIL_BYTES)
        result = fixtures.MemoryResult(label, raw);nodes.complete_command(phase, result)
        phase['data'] = files.archive_summary(raw, 'run')
        entries['evidence/' + label + '.complete.json'] = model.canonical(result.receipt)
        self.review(contract, entries, report)
        phase['data']['window'] = files.tail_summary(b'')['window']
        with self.assertRaises(model.Refused):self.review(contract, entries, report)


class FileKindCaptureTests(unittest.TestCase):
    def capture_error(self, root, payload):
        client, recorder, run, calls = fixtures.StartupNodeCaptureTests().prepare(root)
        def selected(label, arguments, **options):
            if label == 'startup-file-pillar-error':
                calls.append((label, arguments, options));client.counter += 1
                return fixtures.MemoryResult(f'docker-{client.counter:03d}-{label}',
                                             fixtures.file_archive('error', payload))
            return run(label, arguments, **options)
        with mock.patch.object(client, '_run', side_effect=selected):client.capture_startup_diagnostics()
        return json.loads(recorder.seals[files.REPORT]), calls

    def test_single_error_record_survives_without_guessing_a_tail_boundary(self):
        prefix = b'msg="failed to generate momentum" reason="trie: no such version" note="private-marker'
        payload = prefix + b'x' * (213 - len(prefix) - 2) + b'"\n'
        self.assertEqual(len(payload), 213)
        self.assertEqual(files.tail_summary(payload)['window']['classified_bytes'], 0)
        with tempfile.TemporaryDirectory(prefix='single-error-regular-') as tmp:
            report, calls = self.capture_error(Path(tmp), payload)
        item = report['nodes'][0]['files'][1];data = item['phase']['data']
        self.assertEqual((report['format'], item['method'], item['phase']['status']),
                         ('owned-devnet-startup-file-logs/v4', 'whole-file', 'OBSERVED'))
        self.assertEqual(data['content']['bytes'], 213)
        self.assertEqual(data['log']['total_lines'], 1)
        self.assertEqual(data['classification']['reasons']['state_version_missing'], 1)
        self.assertNotIn('window', data);self.assertNotIn('private-marker', json.dumps(report))
        self.assertEqual(len(calls), 17)

    def test_oversized_error_refuses_without_a_tail_retry(self):
        with tempfile.TemporaryDirectory(prefix='large-error-regular-') as tmp:
            report, calls = self.capture_error(Path(tmp), b'x' * (nodes.LOG_BYTES + 1))
        selected = [c for c in calls if c[0] == 'startup-file-pillar-error']
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0][1][:2], ['container', 'cp'])
        self.assertEqual(selected[0][2], {'timeout': 5, 'stdout_cap': files.ARCHIVE_BYTES, 'stderr_cap': 4096})
        phase = report['nodes'][0]['files'][1]['phase']
        self.assertEqual(phase['status'], 'REFUSED');self.assertIsNone(phase['data'])
        self.assertEqual(report['status'], 'UNKNOWN');self.assertEqual(len(calls), 17)

    def test_file_kind_is_explicit_and_does_not_change_the_v3_selector(self):
        state = MethodTests().state()
        self.assertEqual(files.read_method(state), 'byte-tail')
        self.assertEqual(files.read_method_for_file(state, 'run'), 'byte-tail')
        self.assertEqual(files.read_method_for_file(state, 'error'), 'whole-file')
        for kind in (None, True, [], 'other'):
            with self.subTest(kind=kind), self.assertRaises(model.Refused):
                files.read_method_for_file(state, kind)
        state['fields']['Running'] = 1
        with self.assertRaises(model.Refused):files.read_method_for_file(state, 'error')


class FileKindReviewTests(unittest.TestCase):
    def fixture(self):
        contract, entries, report = MixedReviewTests().fixture()
        report['format'] = 'owned-devnet-startup-file-logs/v4'
        for row in report['nodes']:
            for item in row['files']:
                method = 'whole-file' if item['kind'] == 'error' or row['service'] == 'pillar3' else 'byte-tail'
                item['method'] = method;phase = item['phase'];label = phase['command']
                raw = fixtures.file_archive(item['kind']) if method == 'whole-file' else fixtures.file_tail()
                result = fixtures.MemoryResult(label, raw);nodes.complete_command(phase, result)
                phase['data'] = (files.archive_summary(raw, item['kind']) if method == 'whole-file'
                                 else files.tail_summary(raw))
                entries['evidence/' + label + '.complete.json'] = model.canonical(result.receipt)
        entries['evidence/' + files.REPORT] = model.canonical(report)
        return contract, entries, report

    def test_reader_binds_both_kind_and_state_without_header_authority(self):
        contract, entries, report = self.fixture()
        checked = ReviewTests().review(contract, entries, report)['startup_file_log_diagnostics']
        self.assertTrue(checked['diagnostic_assertions_only'])
        self.assertFalse(checked['original_tar_or_text_independently_rechecked'])
        self.assertFalse(checked['summary']['accepted_header_authority'])
        for row in checked['summary']['nodes']:
            for item in row['files']:
                expected = 'whole-file' if item['kind'] == 'error' or row['service'] == 'pillar3' else 'byte-tail'
                self.assertEqual(item['method'], expected)
                self.assertEqual('window' in item['phase']['data'], expected == 'byte-tail')

    def test_running_error_cannot_be_relabelled_as_a_tail(self):
        contract, entries, report = self.fixture();report['nodes'][0]['files'][1]['method'] = 'byte-tail'
        with self.assertRaisesRegex(model.Refused, 'review_file_log_method_binding'):
            ReviewTests().review(contract, entries, report)

    def test_v3_and_v4_cannot_be_interchanged_without_their_recorded_method_policy(self):
        contract, entries, report = MixedReviewTests().fixture()
        report['format'] = 'owned-devnet-startup-file-logs/v4'
        with self.assertRaisesRegex(model.Refused, 'review_file_log_method_binding'):
            ReviewTests().review(contract, entries, report)
        contract, entries, report = self.fixture();report['format'] = 'owned-devnet-startup-file-logs/v3'
        with self.assertRaisesRegex(model.Refused, 'review_file_log_method_binding'):
            ReviewTests().review(contract, entries, report)


if __name__ == '__main__':
    unittest.main()
