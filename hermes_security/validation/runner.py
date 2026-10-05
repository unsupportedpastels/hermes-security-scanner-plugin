"""Bounded disposable-copy harnesses and exact-origin HTTP probes.

A copy plus rlimits is not a hostile-code filesystem sandbox. Without unshare,
proxy variables are best-effort only; callers must expose this limitation.
"""
import functools
import math
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from hermes_security.canonical import utcnow
from hermes_security.errors import PolicyDenied, NotFound
from .policy import check_plan, normalize_origin
from .plans import execution_limits, control_spec
from .receipts import build_receipt

_GRANT_LOCK=threading.RLock()

@functools.lru_cache(maxsize=1)
def network_isolation_available():
    """Probe the actual current user's namespace support once, not just PATH."""
    executable=shutil.which('unshare')
    if not executable: return False
    try:
        return subprocess.run([executable,'-rn','--','true'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3).returncode==0
    except (OSError,subprocess.TimeoutExpired): return False

def _process_limit():
    # RLIMIT_NPROC counts the entire real UID's threads, not this harness.
    # Preserve room for a bounded harness without breaking busy shared hosts.
    if not hasattr(resource,'RLIMIT_NPROC') or os.geteuid()==0: return None
    try:
        threads=sum(len(list((p/'task').iterdir())) for p in Path('/proc').iterdir()
                    if p.name.isdigit() and p.stat().st_uid==os.getuid())
    except OSError:
        return None  # cannot safely establish a per-UID baseline
    _,hard=resource.getrlimit(resource.RLIMIT_NPROC)
    return threads+64 if hard==resource.RLIM_INFINITY else min(threads+64,hard)

def _limits(timeout,nproc):
    resource.setrlimit(resource.RLIMIT_CPU,(max(1,math.ceil(timeout)),max(2,math.ceil(timeout)+1)))
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024**2,64*1024**2))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if nproc is not None: resource.setrlimit(resource.RLIMIT_NPROC,(nproc,nproc))

def _kill(proc):
    try: os.killpg(proc.pid,signal.SIGKILL)
    except ProcessLookupError: pass

def _command(argv,cwd,timeout,cap,isolated):
    env={'PATH':os.defpath,'HOME':str(cwd),'TMPDIR':str(cwd),'LANG':'C.UTF-8',
         'http_proxy':'http://127.0.0.1:9','https_proxy':'http://127.0.0.1:9',
         'HTTP_PROXY':'http://127.0.0.1:9','HTTPS_PROXY':'http://127.0.0.1:9','ALL_PROXY':'http://127.0.0.1:9','all_proxy':'http://127.0.0.1:9','no_proxy':'','NO_PROXY':''}
    if isolated: argv=[shutil.which('unshare'),'-rn','--',*argv]
    nproc=_process_limit()
    proc=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                          start_new_session=True,preexec_fn=lambda:_limits(timeout,nproc))
    data=bytearray(); timed=False; truncated=False; deadline=time.monotonic()+timeout
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout,selectors.EVENT_READ)
            while sel.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0: timed=True;_kill(proc);break
                for key,_ in sel.select(min(remaining,.05)):
                    chunk=os.read(key.fileobj.fileno(),min(65536,cap+1-len(data)))
                    if not chunk: sel.unregister(key.fileobj);break
                    data.extend(chunk)
                    if len(data)>cap: truncated=True;_kill(proc);break
                if truncated: break
        if not timed and not truncated:
            try: proc.wait(timeout=max(.001,deadline-time.monotonic()))
            except subprocess.TimeoutExpired: timed=True
    finally:
        _kill(proc)  # also terminate descendants which survived the leader
        proc.wait();proc.stdout.close()
    return {'output':bytes(data[:cap]).decode('utf-8','replace'),'exitCode':proc.returncode,
            'timeout':timed,'truncated':truncated,'complete':not timed and not truncated and proc.returncode==0}

def _observations(results,pi,ni,marker):
    controls=[]
    for i in (pi,ni):
        r=results[i]
        controls.append({'ran':True,'matched':marker in r['output'],'complete':r['complete'],
                         **{k:v for k,v in r.items() if k not in {'output','complete'}}})
    p,n=controls
    status='inconclusive' if not p['complete'] or not n['complete'] else ('passed' if p['matched'] and not n['matched'] else 'failed')
    return p,n,status

def run_local(plan, *, target, workdir_parent, grant=None):
    """Run argv in a fresh copy. Caller must establish explicit user opt-in."""
    check_plan(plan,grant=grant,safety_level=plan.get('level','static'),now=utcnow())
    if plan.get('kind')!='local-command': raise PolicyDenied('run_local requires local-command')
    timeout,cap=execution_limits(plan)
    pi,ni,marker=control_spec(plan,len(plan['commands']))
    root=Path(target['root'] if isinstance(target,dict) else target).resolve(strict=True)
    parent=Path(workdir_parent).resolve(strict=True)
    if parent==root or root in parent.parents: raise PolicyDenied('workdir_parent cannot be inside target')
    started=utcnow(); scratch=Path(tempfile.mkdtemp(prefix='validation-',dir=parent)); copy=scratch/'target'
    results=[]; notes=[]; cleanup={'done':False,'detail':'cleanup not completed'}
    try:
        shutil.copytree(root,copy,symlinks=True)
        for path in copy.rglob('*'):
            if path.is_symlink():
                try: resolved=path.resolve()
                except (OSError,RuntimeError) as exc: raise PolicyDenied('invalid copied symlink') from exc
                if not resolved.is_relative_to(copy): raise PolicyDenied('copied symlink points outside disposable copy')
        isolated=network_isolation_available()
        notes.append('network isolation: unshare -rn' if isolated else 'network isolation: best-effort')
        notes.append('Disposable copy is not filesystem isolation; only explicitly requested trusted harnesses may run.')
        for argv in plan['commands']:
            try: results.append(_command(argv,copy,timeout,cap,isolated))
            except (OSError,subprocess.SubprocessError):
                results.append({'output':'command could not start','complete':False,'exitCode':None,'timeout':False,'truncated':False})
    finally:
        try: shutil.rmtree(scratch)
        except OSError: pass
        cleanup={'done':not scratch.exists(),'detail':'disposable copy removed' if not scratch.exists() else 'disposable copy cleanup failed'}
    positive,negative,status=_observations(results,pi,ni,marker)
    if not cleanup['done']: status='inconclusive'
    return build_receipt(plan,status=status,positive=positive,negative=negative,started_at=started,cleanup=cleanup,
                         output='\n'.join(r['output'] for r in results),notes=notes)

class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self,origin,notes): self.origin,self.notes=origin,notes
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        # Stop all redirects, including same-origin, so each request is charged
        # before dispatch and redirect chains can never bypass the request cap.
        if normalize_origin(newurl)!=self.origin: self.notes.append('cross-origin redirect refused')
        else: self.notes.append('same-origin redirect stopped; submit a separately budgeted request')
        return None

def run_http(plan, *, grant, store=None):
    """Probe only authorized origins; charge every attempted request before I/O.

    The lock serializes in-process grants. Multi-process callers must serialize
    dispatch externally: the store contract has no atomic consume operation.
    """
    with _GRANT_LOCK:
        if store is not None:
            try: grant=store.get_grant(grant['grantId'])
            except (KeyError,TypeError,NotFound) as exc: raise PolicyDenied('missing grant') from exc
        check_plan(plan,grant=grant,safety_level=plan.get('level','static'),now=utcnow())
        if plan.get('kind')!='http-probe': raise PolicyDenied('run_http requires http-probe')
        timeout,cap=execution_limits(plan);pi,ni,marker=control_spec(plan,len(plan['requests']),http=True)
        started=utcnow();results=[];notes=[]
        for spec in plan['requests']:
            one=dict(plan,requests=[spec])
            check_plan(one,grant=grant,safety_level=plan['level'],now=utcnow())
            grant['used']=grant.get('used',0)+1
            if store is not None:
                store.grant_validation(grant['scanId'],grant)
                if store.get_grant(grant['grantId'])['used']!=grant['used']: raise PolicyDenied('grant usage persistence failed')
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),_Redirects(normalize_origin(spec['url']),notes))
            body=spec.get('body')
            if body is not None and not isinstance(body,bytes): body=str(body).encode()
            req=urllib.request.Request(spec['url'],data=body,method=spec.get('method','GET'),headers=spec.get('headers',{}))
            response=None
            try:
                try: response=opener.open(req,timeout=timeout)
                except urllib.error.HTTPError as exc: response=exc
                with response:
                    data=response.read(cap+1)
                    code=response.code
                truncated=len(data)>cap
                results.append({'output':data[:cap].decode('utf-8','replace'),'complete':not truncated and not 300<=code<400,'statusCode':code,'truncated':truncated})
            except (OSError,urllib.error.URLError,ValueError):
                results.append({'output':'HTTP request failed','complete':False,'statusCode':None,'truncated':False})
        positive,negative,status=_observations(results,pi,ni,marker)
        return build_receipt(plan,status=status,positive=positive,negative=negative,started_at=started,
                             cleanup={'done':True,'detail':'response handles closed; only declared synthetic non-destructive probes'},
                             output='\n'.join(r['output'] for r in results),notes=notes)
