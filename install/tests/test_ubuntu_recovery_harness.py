import importlib.util, json, subprocess, sys, tempfile, unittest
from pathlib import Path
HARNESS=Path(__file__).parents[1]/"vm"/"test-ubuntu-recovery.py"
spec=importlib.util.spec_from_file_location("recovery",HARNESS);h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
class HarnessTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.d=Path(self.t.name);self.files={}
  for n in ("binary","graph","host_base","target_base","ovmf_code","ovmf_vars","cut_seed","witness_seed","resume_seed"):
   p=self.d/n;p.write_bytes(n.encode());self.files[n]=p
 def tearDown(self):self.t.cleanup()
 def prepare(self):
  w=self.d/"work";args=[sys.executable,str(HARNESS),"prepare","--work",str(w),"--source-revision","dce4b67"]
  for n,p in self.files.items():args += ["--"+n.replace("_","-"),str(p)]
  subprocess.run(args,check=True,capture_output=True);return w
 def test_discovered_prepare_binds_4096_and_all_inputs(self):
  w=self.prepare();m=json.loads((w/"manifest.json").read_text());self.assertEqual(m["memory_mib"],4096);self.assertEqual(m["schema"],h.SCHEMA)
 def test_prepare_never_overwrites(self):
  w=self.prepare();args=[sys.executable,str(HARNESS),"prepare","--work",str(w),"--source-revision","x"]
  for n,p in self.files.items():args += ["--"+n.replace("_","-"),str(p)]
  self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)
 def test_digest_drift_refused(self):
  w=self.prepare();self.files["graph"].write_bytes(b"drift")
  with self.assertRaises(SystemExit):h.load(w/"manifest.json")
 def test_timestamped_real_marker_is_matched(self):
  self.assertRegex("[  44.2] JSTK_UBUNTU_COMMIT seq=1 offset=0 length=64",h.MARKERS["commit"])
 def test_case_id_containment_and_comma_paths_fail_closed(self):
  for bad in ("../escape","/absolute","a/b",""):
   with self.assertRaises(SystemExit):h.case_paths(self.d,bad)
  comma=self.d/"bad,name";comma.write_bytes(b"x")
  with self.assertRaises(SystemExit):h.regular(comma)
 def test_work_path_rejects_comma_and_symlink_ancestor(self):
  with self.assertRaises(SystemExit):h.safe_work(self.d/"bad,work",False)
  real=self.d/"real-parent";real.mkdir();alias=self.d/"alias";alias.symlink_to(real,target_is_directory=True)
  with self.assertRaises(SystemExit):h.safe_work(alias/"work",False)
 def test_later_phase_symlink_is_not_regular(self):
  real=self.d/"real";real.write_bytes(b"x");link=self.d/"link";link.symlink_to(real)
  with self.assertRaises(SystemExit):h.regular(link)
 def test_process_identity_rejects_non_qemu_pid(self):
  with self.assertRaises(SystemExit):h.proc_identity(subprocess.os.getpid())
 def valid_witness(self):
  return {"case_id":"c","journal_sha256":"a"*64,"journal_bytes":10,"last_valid_kind":"Intent","last_valid_seq":4,"last_valid_offset":64,"last_valid_length":64,"next_offset":64,"pending_intent":True,"target_range_sha256":"b"*64,"artifact_range_sha256":"b"*64,"range_equal":True,"committed_previous_equal":True}
 def test_witness_rejects_boolean_digest_and_cursor_contradictions(self):
  h.validate_witness(self.valid_witness(),"c")
  for key,value in (("pending_intent",1),("range_equal",False),("committed_previous_equal",False),("next_offset",65),("last_valid_seq",-1)):
   frame=self.valid_witness();frame[key]=value
   with self.assertRaises(SystemExit,msg=key):h.validate_witness(frame,"c")
 def test_nonzero_witness_exit_is_refused(self):
  r=self.d/"case";r.mkdir();(r/"witness.exit.json").write_text('{"returncode":1}')
  a=type("A",(),{"run":r,"case_id":"case"})()
  with self.assertRaises(SystemExit):h.witness(a)
 def test_fixed_qemu_is_offline_and_uses_only_bound_disks(self):
  w=self.prepare();m=h.load(w/"manifest.json");p=h.case_paths(w,"c")
  for k in ("host","target","vars"):p[k].parent.mkdir(parents=True,exist_ok=True);p[k].touch(exist_ok=True)
  argv=h.qemu_argv(m,p,"cut",p["run"]/"s")
  self.assertIn("none",argv[argv.index("-nic")+1:]);self.assertFalse(any("netdev" in x for x in argv));self.assertNotIn("/dev/sd", " ".join(argv))
if __name__=="__main__":unittest.main()
