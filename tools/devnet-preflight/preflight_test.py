#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
MODULE = Path(__file__).with_name("preflight.py")
spec = importlib.util.spec_from_file_location("devnet_resource_preflight", MODULE)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def facts():
    return {"platform":"linux", "architecture":"x86_64", "effective_cpus":4,
        "memory_total_bytes":16*p.GIB, "memory_available_bytes":14*p.GIB,
        "disk_total_bytes":64*p.GIB, "disk_free_bytes":32*p.GIB,
        "docker_client":"28.0.4", "docker_server":"28.0.4",
        "compose":"2.38.2", "cgroup_version":"2", "containers":0}


class Controls(unittest.TestCase):
    def invoke(self, values=None, args=None, collector=None, writer=p.write_report):
        output, errors = io.StringIO(), io.StringIO()
        if collector is None:
            collector = lambda path, commands: copy.deepcopy(facts() if values is None else values)
        code = p.run(["--workspace", "/PRIVATE/operator/work"] + (args or []),
                     output, errors, collector=collector, writer=writer)
        return code, output.getvalue(), errors.getvalue()

    def test_complete_observation_has_no_setup_authority(self):
        code, raw, errors = self.invoke()
        value=json.loads(raw)
        self.assertEqual((code,errors,value["status"],value["eligible"]),(0,"","COMPLETE",True))
        for field in ("setup_authorized","services_started","signing_or_transactions_started"):
            self.assertFalse(value[field])
        self.assertNotIn("PRIVATE",raw)
        self.assertEqual(value["scope"],"READ_ONLY_RESOURCE_OBSERVATION")

    def test_resource_refusals_and_explicit_gate_exit(self):
        for name,key,new in (
            ("cpu","effective_cpus",3),("memory","memory_available_bytes",11*p.GIB),
            ("disk","disk_free_bytes",17*p.GIB),("engine","containers",1),
            ("docker","docker_server","20.9.9"),("compose","compose","2.19.9"),
            ("cgroup","cgroup_version","1")):
            values=facts();values[key]=new
            with self.subTest(case=name):
                code,raw,_=self.invoke(values)
                self.assertEqual(code,0)
                self.assertFalse(json.loads(raw)["eligible"])
                code,raw,_=self.invoke(values,["--require-eligible"])
                self.assertEqual(code,2)
                self.assertFalse(json.loads(raw)["eligible"])

    def test_exact_disk_and_memory_boundaries(self):
        values=facts()
        values.update(disk_free_bytes=18*p.GIB,memory_available_bytes=12*p.GIB)
        self.assertTrue(json.loads(self.invoke(values)[1])["eligible"])
        values["disk_free_bytes"]-=1
        self.assertFalse(json.loads(self.invoke(values)[1])["eligible"])
        values["disk_free_bytes"]=18*p.GIB
        values["memory_available_bytes"]-=1
        self.assertFalse(json.loads(self.invoke(values)[1])["eligible"])

    def test_invalid_observations_remain_unknown(self):
        for name,key,new in (
            ("boolean","effective_cpus",True),("negative","containers",-1),
            ("nonfinite","disk_free_bytes",float("nan")),
            ("inconsistent-disk","disk_free_bytes",65*p.GIB),
            ("inconsistent-memory","memory_available_bytes",17*p.GIB),
            ("platform","platform","PRIVATE"),("version","compose","PRIVATE secret"),
            ("suffix","docker_server","28.0.4-PRIVATE"),
            ("cgroup-type","cgroup_version",2),
            ("cgroup-content","cgroup_version","PRIVATE")):
            values=facts();values[key]=new
            with self.subTest(case=name):
                code,raw,errors=self.invoke(values)
                report=json.loads(raw)
                self.assertEqual((code,report["status"],report["eligible"]),(70,"UNKNOWN",None))
                self.assertIsNone(report["facts"])
                self.assertNotIn("PRIVATE",raw+errors)
        values=facts();values["PRIVATE_extra"]="PRIVATE"
        self.assertEqual(self.invoke(values)[0],70)
        values=facts();del values["compose"]
        self.assertEqual(self.invoke(values)[0],70)

    def test_argument_refusals_do_not_probe_or_echo(self):
        def unavailable(*args):
            self.fail("argument refusal called the collector")
        for args in (["--PRIVATE-flag"],["--minimum-free-bytes",str(9*p.GIB)],
                     ["--expected-allocation-bytes","-1"],
                     ["--expected-allocation-bytes","01"],
                     ["--expected-allocation-bytes","18446744073709551616"]):
            with self.subTest(args=args):
                code,raw,errors=self.invoke(args=args,collector=unavailable)
                self.assertEqual((code,raw),(64,""))
                self.assertNotIn("PRIVATE",errors)

    def test_unknown_probe_and_output_errors_are_private(self):
        def failure(*args):
            raise OSError("PRIVATE endpoint or path")
        code,raw,errors=self.invoke(collector=failure)
        self.assertEqual(code,70)
        self.assertNotIn("PRIVATE",raw+errors)
        def write_failure(*args):
            raise FileExistsError("PRIVATE report")
        code,raw,errors=self.invoke(writer=write_failure)
        self.assertEqual((code,raw),(70,""))
        self.assertNotIn("PRIVATE",errors)
        class Dropped:
            def write(self,raw):return None
        with self.assertRaises(p.Refusal):
            p.write_report(b"complete\n",None,Dropped())

    def test_memory_schema_and_safe_versions(self):
        self.assertEqual(p.memory("MemTotal: 16384 kB\nMemAvailable: 8192 kB\n")["MemAvailable"],8192*1024)
        for raw in ("MemTotal: 1 kB\n", "MemTotal: 1 kB\nMemAvailable: 2 kB\n",
                    "MemTotal: 2 kB\nMemAvailable: 1 kB\nMemTotal: 2 kB\n"):
            with self.subTest(raw=raw),self.assertRaises(p.Refusal):
                p.memory(raw)
        self.assertEqual(p.core("v28.0.4-vendor"),"28.0.4")
        for raw in ("PRIVATE","1.2", "1.2.3\nPRIVATE","65536.0.0"):
            with self.subTest(raw=raw),self.assertRaises(p.Refusal):
                p.version(raw)

    def test_non_linux_probe_stops_before_commands(self):
        with mock.patch.object(p.platform,"system",return_value="Darwin"):
            with self.assertRaises(p.Refusal):
                p.collect("/PRIVATE",[])

    def test_failed_command_preserves_actual_outcome_without_raw_cause(self):
        captured={"actual_exit":7,"complete":True,"reason":None,
                  "stdout":b"PRIVATE","stderr":b"PRIVATE endpoint","streams":{}}
        records=[]
        with mock.patch.object(p,"capture",return_value=captured):
            with self.assertRaises(p.Refusal):
                p.command("docker_version",["docker","version"],records)
        self.assertEqual(records[0]["actual_exit"],7)
        self.assertTrue(records[0]["capture_complete"])
        self.assertNotIn("PRIVATE",json.dumps(records))

    @unittest.skipUnless(os.name=="posix","POSIX capture controls; the resource probe supports Linux")
    def test_owned_child_capture_success(self):
        result=p.capture([sys.executable,"-I","-B","-c","print('ok',end='')"])
        self.assertEqual((result["actual_exit"],result["complete"],result["stdout"]),(0,True,b"ok"))

    @unittest.skipUnless(os.name=="posix","POSIX capture controls; the resource probe supports Linux")
    def test_owned_child_capture_bound(self):
        result=p.capture([sys.executable,"-I","-B","-c","import os; os.write(1,b'x'*32768)"],cap=1024)
        self.assertFalse(result["complete"])
        self.assertEqual(result["reason"],"output_bound")
        self.assertLessEqual(len(result["stdout"]),1024)
        self.assertGreater(result["streams"]["stdout"]["observed_bytes"],1024)

    @unittest.skipUnless(os.name=="posix","POSIX capture controls; the resource probe supports Linux")
    def test_failed_pipe_read_preserves_actual_exit(self):
        def failure(*args):
            raise OSError("PRIVATE pipe cause")
        result=p.capture([sys.executable,"-I","-B","-c","print('ok')"],reader=failure)
        self.assertFalse(result["complete"])
        self.assertEqual(result["reason"],"capture_read_failed")
        self.assertIsInstance(result["actual_exit"],int)
        self.assertNotIn("PRIVATE",result["reason"])

    @unittest.skipUnless(os.name=="posix","POSIX capture controls; the resource probe supports Linux")
    def test_owned_child_capture_timeout(self):
        result=p.capture([sys.executable,"-I","-B","-c","import time; time.sleep(2)"],timeout=0.05)
        self.assertFalse(result["complete"])
        self.assertEqual(result["reason"],"timeout")
        self.assertIsInstance(result["actual_exit"],int)


class Result(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.subtests=0
    def addSubTest(self,test,subtest,err):
        self.subtests+=1
        super().addSubTest(test,subtest,err)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--receipt")
    parser.add_argument("--diagnostics",action="store_true")
    args=parser.parse_args()
    result=Result()
    unittest.defaultTestLoader.loadTestsFromTestCase(Controls).run(result)
    failed=[test.id().split(" (",1)[0]for test,_ in result.failures+result.errors]
    revision=os.environ.get("GITHUB_SHA","")
    receipt={"format":"zenon-devnet-resource-controls/v1",
        "source_revision":revision if p.re.fullmatch("[0-9a-f]{40}",revision)else None,
        "tool_sha256":hashlib.sha256(MODULE.read_bytes()).hexdigest(),
        "test_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "platform":sys.platform,"tests":result.testsRun,"subtests":result.subtests,
        "skipped":[test.id()for test,_ in result.skipped],"failed":failed,
        "status":"PASS"if result.wasSuccessful()else"FAILURE",
        "scope":"logic, privacy and owned foreground child controls; no devnet"}
    raw=(json.dumps(receipt,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
    p.write_report(raw,args.receipt,sys.stdout)
    if args.diagnostics:
        for test,trace in result.failures+result.errors:
            print(test.id(),trace,file=sys.stderr)
    return 0 if result.wasSuccessful()else 1


if __name__=="__main__":
    raise SystemExit(main())
