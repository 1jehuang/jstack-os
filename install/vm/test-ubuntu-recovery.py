#!/usr/bin/env python3
"""Sequential, overlay-only Ubuntu recovery QEMU campaign harness.

QEMU is never run by ``prepare``. ``start`` launches a detached supervisor which
owns the campaign lock until its QEMU child exits. The fixed argv has no network
backend and accepts only regular qcow2/ISO inputs bound by the manifest.
"""
from __future__ import annotations
import argparse, fcntl, hashlib, json, os, re, shutil, signal, subprocess, sys, time
from pathlib import Path
from typing import Any, NoReturn

SCHEMA = "jstack.ubuntu-recovery-campaign.v2"
PREFIX = "JSTK_VM_COLD_WITNESS="
MARKERS = {
 "intent": r"JSTK_UBUNTU_INTENT\s", "write": r"JSTK_UBUNTU_WRITE_BEGIN\s",
 "readback": r"JSTK_UBUNTU_READBACK_OK\s", "commit": r"JSTK_UBUNTU_COMMIT\s",
 "advance": r"JSTK_UBUNTU_ADVANCE\s", "complete": r"JSTK_UBUNTU_COMPLETE\s",
}
HEX = re.compile(r"^[0-9a-f]{64}$")
CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")

def die(s: str) -> NoReturn: raise SystemExit("REFUSED: " + s)
def digest(p: Path) -> str:
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
 return h.hexdigest()
def regular(p: Path, suffix: str|None=None) -> Path:
 try: raw=p.lstat()
 except FileNotFoundError: die(f"missing input {p}")
 if p.is_symlink() or not p.is_absolute() or "," in str(p): die(f"unsafe input {p}")
 p=p.resolve(); st=p.stat()
 if not p.is_file() or st.st_nlink != 1 or (suffix and p.suffix != suffix): die(f"unsafe input {p}")
 return p
def safe_work(path:Path, existing:bool)->Path:
 if not path.is_absolute() or "," in str(path): die("unsafe work path")
 current=Path(path.anchor)
 parts=path.parts[1:] if path.anchor else path.parts
 check=parts[:-1]
 for part in check:
  current=current/part
  try: st=current.lstat()
  except FileNotFoundError: die("work parent does not exist")
  if current.is_symlink() or not current.is_dir(): die("work path has unsafe ancestor")
 resolved=path.resolve()
 if "," in str(resolved): die("unsafe resolved work path")
 return resolved
def put(path: Path, value: Any) -> None:
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"w") as f: json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def bound(p: Path) -> dict[str,Any]: return {"path":str(regular(p)),"sha256":digest(p)}
def load(path: Path) -> dict[str,Any]:
 path=safe_work(path,True); regular(path)
 m=json.loads(path.read_text())
 if m.get("schema") != SCHEMA: die("wrong manifest schema")
 allowed={"schema","source_revision","memory_mib","cpus","binary","graph","host_base","target_base","ovmf_code","ovmf_vars","cut_seed","witness_seed","resume_seed"}
 if set(m) != allowed or m.get("memory_mib") != 4096 or not isinstance(m.get("cpus"),int) or not 1 <= m["cpus"] <= 8: die("invalid or extended manifest")
 for k in ("binary","graph","host_base","target_base","ovmf_code","ovmf_vars","cut_seed","witness_seed","resume_seed"):
  p=regular(Path(m[k]["path"])); expected=m[k].get("sha256","")
  if not HEX.fullmatch(expected) or digest(p)!=expected: die(f"{k} digest changed")
 return m

def prepare(a):
 w=safe_work(a.work,False)
 if w.exists(): die("work directory exists")
 w.mkdir(mode=0o700)
 m={"schema":SCHEMA,"source_revision":a.source_revision,"memory_mib":4096,"cpus":a.cpus,
    "binary":bound(a.binary),"graph":bound(a.graph),"host_base":bound(a.host_base),
    "target_base":bound(a.target_base),"ovmf_code":bound(a.ovmf_code),"ovmf_vars":bound(a.ovmf_vars),
    "cut_seed":bound(a.cut_seed),"witness_seed":bound(a.witness_seed),"resume_seed":bound(a.resume_seed)}
 put(w/"manifest.json",m); print(w/"manifest.json")

def overlay(base: Path,out: Path,qemu_img: str):
 if out.exists(): die("overlay exists")
 subprocess.run([qemu_img,"create","-q","-f","qcow2","-F","qcow2","-b",str(base),str(out)],check=True)
def case_paths(w:Path,c:str)->dict[str,Path]:
 if not CASE_ID.fullmatch(c): die("invalid case id")
 r=w/"cases"/c
 return {"run":r,"host":r/"host.qcow2","target":r/"target.qcow2","vars":r/"vars.fd"}
def qemu_argv(m,p,phase,serial):
 seed=Path(m[phase+"_seed"]["path"])
 return ["qemu-system-x86_64","-enable-kvm","-cpu","host","-m",str(m["memory_mib"]),
  "-smp",str(m["cpus"]),"-display","none","-monitor","none","-nic","none","-no-reboot",
  "-drive",f"if=pflash,format=raw,readonly=on,file={m['ovmf_code']['path']}",
  "-drive",f"if=pflash,format=raw,file={p['vars']}",
  "-drive",f"file={p['host']},if=none,id=recovery,format=qcow2",
  "-device","virtio-blk-pci,drive=recovery,serial=JSTACK_RECOVERY_01,bootindex=1",
  "-drive",f"file={p['target']},if=none,id=target,format=qcow2",
  "-device","virtio-blk-pci,drive=target,serial=JSTACK_TARGET_01",
  "-drive",f"file={seed},if=virtio,format=raw,readonly=on",
  "-chardev",f"file,id=serial0,path={serial}","-serial","chardev:serial0"]
def start(a):
 mp=a.manifest.resolve();m=load(mp);w=mp.parent;p=case_paths(w,a.case_id)
 if a.phase=="cut":
  p["run"].mkdir(parents=True,mode=0o700)
  overlay(Path(m["host_base"]["path"]),p["host"],a.qemu_img);overlay(Path(m["target_base"]["path"]),p["target"],a.qemu_img)
  shutil.copyfile(m["ovmf_vars"]["path"],p["vars"])
 else:
  for k in ("host","target","vars"): regular(p[k])
 serial=p["run"]/(a.phase+".serial.log"); serial.open("x").close()
 cmd=[sys.executable,str(Path(__file__).resolve()),"_supervise","--manifest",str(mp),"--case-id",a.case_id,"--phase",a.phase]
 proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 put(p["run"]/(a.phase+".supervisor.json"),{"pid":proc.pid,"started":int(time.time())});print(proc.pid)
def proc_identity(pid:int)->dict[str,Any]:
 try:
  stat=Path(f"/proc/{pid}/stat").read_text();cmd=Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
 except (FileNotFoundError,PermissionError): die("QEMU process is absent or unreadable")
 if not cmd or Path(cmd[0].decode(errors="replace")).name != "qemu-system-x86_64": die("PID is not the supervised QEMU")
 return {"starttime":stat.rsplit(")",1)[1].split()[19],"cmdline_sha256":hashlib.sha256(b"\0".join(cmd)).hexdigest()}
def supervise(a):
 mp=a.manifest.resolve();m=load(mp);w=mp.parent;p=case_paths(w,a.case_id);phase=a.phase
 lock=(w/"campaign.lock").open("a+");fcntl.flock(lock,fcntl.LOCK_EX)
 serial=p["run"]/(phase+".serial.log")
 log=(p["run"]/(phase+".qemu.log")).open("xb")
 proc=subprocess.Popen(qemu_argv(m,p,phase,serial),stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
 try:
  identity=proc_identity(proc.pid)
  put(p["run"]/(phase+".process.json"),{"pid":proc.pid,"identity":identity,"argv":qemu_argv(m,p,phase,serial)})
  rc=proc.wait()
 finally:
  if proc.poll() is None: proc.wait()
 put(p["run"]/(phase+".exit.json"),{"returncode":rc,"finished":int(time.time())})
def cut(a):
 r=a.run.resolve();d=json.loads((r/"cut.process.json").read_text());pid=int(d["pid"])
 if proc_identity(pid) != d.get("identity"): die("stale or substituted QEMU PID")
 try: pidfd=os.pidfd_open(pid)
 except (AttributeError,OSError): die("cannot bind QEMU process with pidfd")
 pat=re.compile(MARKERS[a.boundary]);end=time.monotonic()+a.timeout
 while time.monotonic()<end:
  text=(r/"cut.serial.log").read_text(errors="replace")
  hits=[x for x in text.splitlines() if pat.search(x)]
  if hits:
   if proc_identity(pid) != d.get("identity"): die("QEMU identity changed before cut")
   signal.pidfd_send_signal(pidfd,signal.SIGKILL)
   os.close(pidfd);put(r/"cut-request.json",{"intended_boundary":a.boundary,"observed_marker":hits[-1],"pid":pid,"identity":d["identity"]});print(hits[-1]);return
  try: os.kill(pid,0)
  except ProcessLookupError: die("QEMU exited before marker")
  time.sleep(.2)
 os.close(pidfd);die("marker timeout; detached supervisor and QEMU remain running")
def witness(a):
 r=a.run.resolve(); exitp=r/"witness.exit.json"
 if not exitp.exists(): die("witness VM has not exited")
 if json.loads(exitp.read_text()).get("returncode") != 0: die("witness VM did not power off cleanly")
 lines=(r/"witness.serial.log").read_text(errors="replace").splitlines(); frames=[]
 for x in lines:
  if PREFIX in x: frames.append(json.loads(x.split(PREFIX,1)[1]))
 if len(frames)!=1: die("expected exactly one cold witness frame")
 f=frames[0]; required=("case_id","journal_sha256","journal_bytes","last_valid_kind","last_valid_seq","next_offset","pending_intent","target_range_sha256","artifact_range_sha256","range_equal","committed_previous_equal")
 if any(k not in f for k in required) or f["case_id"]!=a.case_id: die("invalid witness frame")
 for k in ("journal_sha256","target_range_sha256","artifact_range_sha256"):
  if not HEX.fullmatch(str(f[k])): die("invalid witness digest")
 intended=json.loads((r/"cut-request.json").read_text())["intended_boundary"]
 kind=f["last_valid_kind"]; equal=f["range_equal"]
 if kind=="Intent" and equal: actual="readback-or-effect-complete-before-commit"
 elif kind=="Intent": actual="intent-or-partial-write"
 elif kind=="Commit": actual="commit-before-advance"
 elif kind=="Advance": actual="advance"
 elif kind=="Complete": actual="complete"
 else: actual="other"
 exact={"readback":"readback-or-effect-complete-before-commit","commit":"commit-before-advance","advance":"advance","complete":"complete"}
 f["actual_boundary"]=actual;f["intended_boundary"]=intended;f["intended_cut_matched"]=(exact.get(intended)==actual)
 st=(r/"target.qcow2").stat();f["target_qcow_host"]={"size":st.st_size,"mtime_ns":st.st_mtime_ns,"blocks":st.st_blocks}
 put(r/"classified.json",f);print(json.dumps(f,sort_keys=True))
 if not f["intended_cut_matched"]: raise SystemExit(2)
def main():
 ap=argparse.ArgumentParser();s=ap.add_subparsers(dest="cmd",required=True)
 p=s.add_parser("prepare")
 for n in ("work","binary","graph","host_base","target_base","ovmf_code","ovmf_vars","cut_seed","witness_seed","resume_seed"):p.add_argument("--"+n.replace("_","-"),dest=n,type=Path,required=True)
 p.add_argument("--source-revision",required=True);p.add_argument("--cpus",type=int,default=4);p.set_defaults(fn=prepare)
 p=s.add_parser("start");p.add_argument("--manifest",type=Path,required=True);p.add_argument("--case-id",required=True);p.add_argument("--phase",choices=("cut","witness","resume"),required=True);p.add_argument("--qemu-img",default="qemu-img");p.set_defaults(fn=start)
 p=s.add_parser("cut");p.add_argument("--run",type=Path,required=True);p.add_argument("--boundary",choices=MARKERS,required=True);p.add_argument("--timeout",type=float,default=600);p.set_defaults(fn=cut)
 p=s.add_parser("classify-witness");p.add_argument("--run",type=Path,required=True);p.add_argument("--case-id",required=True);p.set_defaults(fn=witness)
 p=s.add_parser("_supervise");p.add_argument("--manifest",type=Path,required=True);p.add_argument("--case-id",required=True);p.add_argument("--phase",choices=("cut","witness","resume"),required=True);p.set_defaults(fn=supervise)
 a=ap.parse_args();a.fn(a)
if __name__=="__main__":main()
