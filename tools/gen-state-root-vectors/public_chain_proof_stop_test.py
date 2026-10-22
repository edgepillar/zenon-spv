import copy,hashlib,json,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
M={};exec((HERE/"public_chain_proof_stop_model.py").read_bytes(),M)
C=json.loads((HERE/"testdata/public-chain-proof-stop-contract.json").read_bytes())
def pair(index, worker, start, after=False, root_crossing=False):
 target=C["successful_proof_rows"][index%128]
 root_error="state_tree_not_ready"if after else None
 proof_error="state_tree_not_ready"if after or root_crossing else None
 return {"index":index,"worker":worker,"key_index":index%128,
 "Root_start_ns":start,"Root_end_ns":1005 if root_crossing else start+1,
 "GetProof_start_ns":1006 if root_crossing else start+2,
 "GetProof_end_ns":1105 if root_crossing else start+3,
 "Root":{"error":root_error,"hash":"0"*64 if root_error else C["successful_root"]},
 "GetProof":{"error":proof_error,"row_sha256":None if proof_error else target["row_sha256"],
 "value_nil":True if proof_error else not target["present_in_projection"],"proof_nil":proof_error is not None}}
def fixture(profile="ordinary",overlap=True):
 rows=[]
 for i in range(2048):
  worker=i%16;sequence=i//16
  if worker==0:
   rows.append(pair(i,worker,900 if sequence==0 else 1110+4*sequence,after=sequence>0,root_crossing=sequence==0 and overlap))
  else:rows.append(pair(i,worker,10+4*sequence))
 data={"schema":"public-Chain-proof-Stop-process-v1","profile":profile,
 "node_revision":C["reference_node_revision"],"runtime_tree":C["reference_runtime_tree"],
 "wire_sha256":C["blinded_wire_selection"]["sha256"],"build_race_enabled":profile=="race",
 "init_ready":True,"warmup_completed_ns":1,"warmup_row_sha256s":[r["row_sha256"]for r in C["successful_proof_rows"]],
 "calls":rows,"post_Stop":pair(0,0,5000,after=True),
 "Stop":{"start_ns":1000,"end_ns":1100,"error":None,"ready_after":False,"calls":2,"idempotent_cleanup_error":None},
 "component_total_ns":6000,"consumer_result":"REFUSED"}
 data.update({name:False for name in M["FLAGS"]})
 return data
class ReadStopModelControls(unittest.TestCase):
 def check(self,data=None,contract=None,profile="ordinary"):
  return M["validate"](C if contract is None else contract,fixture(profile)if data is None else data,profile)
 def test_separate_ordinary_and_race_profiles_match_only_the_component_contract(self):
  for profile in("ordinary","race"):
   result=self.check(profile=profile);self.assertEqual(result["status"],"MATCH")
   self.assertEqual(result["individual_Root_and_GetProof_calls"],4354)
   self.assertFalse(result["production_state_value_accepted"]);self.assertFalse(result["internal_database_interleaving_proven"])
 def test_missing_observed_overlap_is_inconclusive(self):
  self.assertEqual(self.check(data=fixture(overlap=False))["status"],"INCONCLUSIVE")
 def test_contract_substitution_is_refused(self):
  for name,value in(("minimum_observed_public_call_intervals_overlapping_Stop",0),("successful_root","0"*64),("reference_node_revision","0"*40)):
   c=copy.deepcopy(C);c[name]=value
   with self.assertRaises(ValueError):self.check(contract=c)
 def test_wrong_root_or_proof_row_digest_is_refused(self):
  for kind in("Root","GetProof"):
   data=fixture();data["calls"][1][kind]["hash"if kind=="Root"else"row_sha256"]="0"*64
   with self.assertRaises(ValueError):self.check(data=data)
 def test_stored_presence_cannot_be_changed_to_absence(self):
  data=fixture();data["calls"][1]["GetProof"]["value_nil"]=not data["calls"][1]["GetProof"]["value_nil"]
  with self.assertRaises(ValueError):self.check(data=data)
 def test_duplicate_missing_and_rebound_requests_are_refused(self):
  for action in("duplicate","missing","key","worker"):
   data=fixture()
   if action=="duplicate":data["calls"][2]=copy.deepcopy(data["calls"][1])
   elif action=="missing":data["calls"].pop()
   elif action=="key":data["calls"][1]["key_index"]=2
   else:data["calls"][1]["worker"]=2
   with self.assertRaises(ValueError):self.check(data=data)
 def test_refusal_cannot_keep_a_payload_or_unknown_error(self):
  for action in("digest","value","proof","class"):
   data=fixture();p=data["calls"][0]["GetProof"]
   if action=="digest":p["row_sha256"]=C["successful_proof_rows"][0]["row_sha256"]
   elif action=="value":p["value_nil"]=False
   elif action=="proof":p["proof_nil"]=False
   else:p["error"]="unselected_error"
   with self.assertRaises(ValueError):self.check(data=data)
 def test_late_success_cannot_survive_completed_Stop(self):
  data=fixture();data["calls"][16]=pair(16,0,1114,after=False)
  with self.assertRaises(ValueError):self.check(data=data)
 def test_error_before_Stop_and_wrong_post_Stop_class_are_refused(self):
  data=fixture();data["calls"][1]=pair(1,1,10,after=True)
  with self.assertRaises(ValueError):self.check(data=data)
  data=fixture();data["post_Stop"]["Root"]["error"]="leveldb_closed"
  with self.assertRaises(ValueError):self.check(data=data)
 def test_integer_and_clock_contracts_are_exact(self):
  for action in("bool","float","negative","reorder","per_worker"):
   data=fixture()
   if action=="bool":data["calls"][1]["index"]=True
   elif action=="float":data["component_total_ns"]=6000.0
   elif action=="negative":data["calls"][1]["Root_start_ns"]=-1
   elif action=="reorder":data["calls"][1]["GetProof_end_ns"]=9
   else:data["calls"][32]=pair(32,0,1110,after=True)
   with self.assertRaises(ValueError):self.check(data=data)
 def test_profile_build_mode_and_input_identity_are_bound(self):
  for action in("race","wire","revision","warmup"):
   data=fixture()
   if action=="race":data["build_race_enabled"]=True
   elif action=="wire":data["wire_sha256"]="0"*64
   elif action=="revision":data["node_revision"]="0"*40
   else:data["warmup_row_sha256s"][0]="0"*64
   with self.assertRaises(ValueError):self.check(data=data)
 def test_Stop_error_readiness_and_cleanup_are_not_success(self):
  for name,value in(("error","failed"),("ready_after",True),("idempotent_cleanup_error","failed"),("calls",True)):
   data=fixture();data["Stop"][name]=value
   with self.assertRaises(ValueError):self.check(data=data)
 def test_unknown_fields_and_unselected_acceptance_are_refused(self):
  for name,value in(("unselected",1),("consumer_result","ACCEPTED"),*[(name,True)for name in M["FLAGS"]]):
   data=fixture();data[name]=value
   with self.assertRaises(ValueError):self.check(data=data)
 def test_refusal_only_overlap_is_inconclusive(self):
  data=fixture();data["calls"][0]["Root"]={"error":"state_tree_not_ready","hash":"0"*64}
  result=self.check(data=data)
  self.assertEqual(result["status"],"INCONCLUSIVE")
  self.assertGreater(result["public_call_intervals_overlapping_Stop"],0)
  self.assertEqual(result["successful_caller_intervals_overlapping_Stop"],0)
 def test_Stop_requires_the_predeclared_completed_query_threshold(self):
  data=fixture()
  for i in range(16,2048):
   if i%16:
    data["calls"][i]=pair(i,i%16,1110+4*(i//16),after=True)
  with self.assertRaises(ValueError):self.check(data=data)
 def test_root_first_framing_of_independent_witnesses_is_refused(self):
  expected=json.loads((HERE/"testdata/public-chain-proof-workload-expectations.json").read_bytes())
  wrong=[]
  for row in expected["expected_rows"]:
   fields=(bytes.fromhex(row["root"]),bytes.fromhex(row["raw_key"]),
    bytes.fromhex(row["value_hex"])if row["present_in_projection"]else None,bytes.fromhex(row["proof_hex"]))
   framed=b"".join(bytes([int(value is not None)])+(0 if value is None else len(value)).to_bytes(8,"big")+(value or b"")for value in fields)
   wrong.append(hashlib.sha256(framed).hexdigest())
  self.assertEqual(len(wrong),128)
  self.assertTrue(all(a!=row["row_sha256"]for a,row in zip(wrong,C["successful_proof_rows"])))
  data=fixture();data["warmup_row_sha256s"]=wrong
  with self.assertRaises(ValueError):self.check(data=data)
if __name__=="__main__":unittest.main(argv=[sys.argv[0]],verbosity=2)
