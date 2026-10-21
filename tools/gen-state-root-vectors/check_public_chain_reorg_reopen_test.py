#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
import hashlib
import contextlib
import io

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("reader",HERE/"check_public_chain_reorg_reopen.py")
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
F=C.load_json(C.H.selected_fixture())
CORPUS_RAW=C.P.read_regular(HERE/"testdata"/C.CORPUS,C.MAX_BYTES)
CORPUS=C.load_json(CORPUS_RAW)
IMAGES={name:{"records":3,"key_bytes":8,"value_bytes":2,"zero_length_values":1,"sha256":str(index)*64}
        for index,name in enumerate(["ledger","cache","tree"],1)}
EVENTS=C.expected_events(F,IMAGES)
def changed():
    return copy.deepcopy(EVENTS)
def row(data,stage,**selection):
    return next(r for values in data.values() for r in values if r["stage"]==stage and all(r.get(k)==v for k,v in selection.items()))

class RecordedSequenceControls(unittest.TestCase):
    def refuse(self,data):
        with self.assertRaises(ValueError): C.validate(data,F)
    def test_complete_synthetic_record_is_scoped(self):
        out=C.validate(EVENTS,F)
        self.assertEqual(out["query_count"],31);self.assertEqual(out["exact_matches"],15)
        self.assertFalse(out["backend_reexecuted"]);self.assertFalse(out["process_freshness_authenticated"])
    def test_missing_old_fork_refusal(self):
        data=changed();r=row(data,"query",checkpoint="after-B3",selection="A2");data["advance-reorg"].remove(r);self.refuse(data)
    def test_extra_event(self):
        data=changed();data["advance-reorg"].append(copy.deepcopy(data["advance-reorg"][-1]));self.refuse(data)
    def test_changed_order(self):
        data=changed();data["advance-reorg"][2],data["advance-reorg"][3]=data["advance-reorg"][3],data["advance-reorg"][2];self.refuse(data)
    def test_foreign_hash_accepted(self):
        data=changed();r=row(data,"query",checkpoint="after-B3",selection="A2");r["root_error"]=r["proof_error"]="none";self.refuse(data)
    def test_height_equal_hash_changed(self):
        data=changed();r=row(data,"frontiers",checkpoint="after-B2");r["frontiers"]["ledger"]={"hash":F["states"]["A2"]["identifier"]["hash"],"height":2};self.refuse(data)
    def test_present_proof_byte_changed(self):
        data=changed();r=row(data,"query",checkpoint="after-A2",selection="A2");r["proof"]=r["proof"][:-2]+"01";self.refuse(data)
    def test_stored_zero_changed_to_absent(self):
        data=changed();r=row(data,"query",checkpoint="after-A2",selection="A2");r["present"]=False;r["value"]="";self.refuse(data)
    def test_absence_changed_to_stored_zero(self):
        data=changed();r=row(data,"query",checkpoint="after-B3",selection="B3");r["present"]=True;r["value"]="00"*32;self.refuse(data)
    def test_projection_patch_changed(self):
        data=changed();r=row(data,"projection",selection="B2");r["patch_dump"]=r["patch_dump"][:-2]+"00";self.refuse(data)
    def test_projection_committed_claim(self):
        data=changed();r=row(data,"projection",selection="A3");r["new_version_error"]="none";self.refuse(data)
    def test_reopen_old_tip(self):
        data=changed();r=row(data,"frontiers",checkpoint="fresh-process-reopen");r["tip"]="A3";self.refuse(data)
    def test_reopen_raw_image_changed(self):
        data=changed();r=row(data,"closed-stores-before-reopen");r["images"]=copy.deepcopy(r["images"]);r["images"]["tree"]["sha256"]="0"*64;self.refuse(data)
    def test_zero_length_rows_omitted(self):
        data=changed();del data["advance-reorg"][-1]["images"]["ledger"]["zero_length_values"];self.refuse(data)
    def test_consensus_claim_changed(self):
        data=changed();data["advance-reorg"][0]["consensus_validation_executed"]=True;self.refuse(data)
    def test_boolean_replaced_by_integer(self):
        data=changed();data["advance-reorg"][0]["consensus_validation_executed"]=0;self.refuse(data)
    def test_reopen_process_record_missing(self):
        data=changed();del data["reopen"];self.refuse(data)
    def test_duplicate_json_key(self):
        with self.assertRaisesRegex(ValueError,"duplicate"):C.load_json(b'{"a":1,"a":2}')
    def test_nonfinite_json(self):
        with self.assertRaisesRegex(ValueError,"non-finite"):C.load_json(b'{"a":NaN}')
    def test_input_cap(self):
        with self.assertRaisesRegex(ValueError,"input cap"):C.load_json(b" "*(1+(2<<20)))

class RecordedCorpusBindingControls(unittest.TestCase):
    def test_image_totals_obey_the_native_row_width_bounds(self):
        for key,value in (("key_bytes",769),("value_bytes",1),("value_bytes",(32<<20)+1)):
            images=copy.deepcopy(IMAGES);images["ledger"][key]=value
            with self.assertRaisesRegex(ValueError,"raw image bounds"):C.validate_images(images)

    def test_self_consistent_substituted_fixture_is_not_the_selected_input(self):
        fixture=copy.deepcopy(F);fixture["states"]["A2"]["root"]="aa"*32
        events=C.expected_events(fixture,IMAGES)
        with self.assertRaisesRegex(ValueError,"fixture digest"):C.validate(events,fixture)

    def test_excessive_json_nesting_returns_clean_refusal(self):
        read=C.P.read_regular
        def selected(path,limit):
            return b"["*2000+b"]"*2000 if Path(path).name=="selected-events.json" else read(path,limit)
        output=io.StringIO()
        with mock.patch.object(C.P,"read_regular",side_effect=selected),contextlib.redirect_stdout(output):
            self.assertEqual(C.main(["--events","selected-events.json"]),1)
        self.assertEqual(json.loads(output.getvalue())["result"],"REFUSED")

    def test_actual_recorded_corpus_has_complete_expected_sequence(self):
        result=C.check_corpus(copy.deepcopy(CORPUS))
        self.assertEqual(result["event_count"],57)
        self.assertEqual(result["query_count"],31)
        self.assertEqual(result["exact_matches"],15)
        self.assertEqual(result["version_refusals"],16)
        self.assertEqual(result["recorded_reference_processes"],2)
        self.assertEqual(result["recorded_reference_builds"],1)
        self.assertEqual(result["reference_processes_executed_by_this_check"],0)

    def test_source_revision_and_tree_substitutions_refuse(self):
        for key in ("revision","runtime_tree","ordinary_build_tree","module_sha256","sum_sha256"):
            value=copy.deepcopy(CORPUS);value["source"][key]="0"*len(value["source"][key])
            with self.assertRaises(ValueError):C.check_corpus(value)

    def test_probe_source_substitution_refuses(self):
        value=copy.deepcopy(CORPUS);value["source"]["probe"]["sha256"]="0"*64
        with self.assertRaises(ValueError):C.check_corpus(value)

    def test_execution_claim_cannot_be_promoted_to_whole_graph_qualification(self):
        value=copy.deepcopy(CORPUS);value["execution"]["whole_module_archive_graph_verification"]="QUALIFIED"
        with self.assertRaises(ValueError):C.check_corpus(value)

    def test_complete_stdout_bytes_are_required(self):
        value=copy.deepcopy(CORPUS);value["cases"][0]["stdout_utf8"]+="\n"
        with self.assertRaisesRegex(ValueError,"exact captured stream"):C.check_corpus(value)

    def test_complete_stderr_bytes_are_required(self):
        value=copy.deepcopy(CORPUS);value["cases"][1]["stderr_utf8"]=""
        with self.assertRaisesRegex(ValueError,"exact captured stream"):C.check_corpus(value)

    def test_marker_is_checked_beyond_stream_hashes(self):
        value=copy.deepcopy(CORPUS)
        changed=value["cases"][1]["stderr_utf8"].replace("PROCESS_COMPLETE","PROCESS_INCOMPLETE")
        value["cases"][1]["stderr_utf8"]=changed
        pin={"bytes":len(changed.encode()),"sha256":hashlib.sha256(changed.encode()).hexdigest()}
        value["cases"][1]["command"]["stderr"]=pin
        value["execution"]["commands"]["reopen"]["stderr"]=pin
        # Only this synthetic mutation bypasses the outer historical pin in memory.
        # Production readers never rebind a recorded execution.
        with mock.patch.object(C,"EXECUTION_SHA256",hashlib.sha256(C.encoded(value["execution"])).hexdigest()):
            with self.assertRaisesRegex(ValueError,"ordinary-process marker"):C.check_corpus(value)

    def test_boolean_exit_is_not_integer_success(self):
        command=copy.deepcopy(CORPUS["cases"][0]["command"]);command["actual_exit"]=False
        with self.assertRaises(ValueError):C.check_command(command)

    def test_incomplete_or_interrupted_capture_refuses(self):
        for key,value in (("output_complete",False),("actual_exit",None),("reason","INTERRUPTED_UNVERIFIED")):
            command=copy.deepcopy(CORPUS["cases"][0]["command"]);command[key]=value
            with self.assertRaises(ValueError):C.check_command(command)

    def test_stream_size_bound_refuses(self):
        command=copy.deepcopy(CORPUS["cases"][0]["command"]);command["stdout"]["bytes"]=(2<<20)+1
        with self.assertRaisesRegex(ValueError,"stream bound"):C.check_command(command)

    def test_acceptance_or_execution_authentication_claims_refuse(self):
        for key in ("accepted_header_binding","runtime_state_value_acceptance","production_qualified",
                    "private_execution_or_distribution_authenticated","cache_account_block_extraction_qualified"):
            value=copy.deepcopy(CORPUS);value["scope"][key]=True
            with self.assertRaises(ValueError):C.check_corpus(value)

    def test_default_file_reader_pins_bytes_and_input_source_closure(self):
        result=C.check_file(HERE/"testdata"/C.CORPUS)
        self.assertEqual(result["corpus_sha256"],C.CORPUS_SHA256)
        self.assertEqual(set(result["reader_inputs_sha256"]),set(C.INPUTS))
        self.assertTrue(set(C.S.INPUTS).issubset(result["reader_inputs_sha256"]))
        self.assertFalse(result["source_and_binary_authenticated"])
        self.assertFalse(result["process_freshness_authenticated"])
        self.assertEqual(result["consumer_result"],"REFUSED")


if __name__=="__main__":
    unittest.main(verbosity=2)
