"""Offline-first scanner execution and deliberately unconfirmed candidates."""
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

from ..canonical import canonical_json, sha256_hex, stable_id, utcnow
from ..errors import ValidationError


def DetectorReceipt(detector, kind='sarif', **values):
    receipt = dict(receiptId=stable_id('det', detector, utcnow(), time.monotonic_ns()),
                   detector=detector, kind=kind, status='ok', executable=None,
                   version=None, ruleVersion=None, commandDigest=None, exitCode=None,
                   durationMs=0, targetFileCount=0, resultCount=0, truncated=False, error=None)
    receipt.update(values)
    return receipt


def safe_run(argv, *, target, work_dir, timeout_s=600, max_output_bytes=50*1024*1024):
    """Drain both pipes with bounded memory, kill the entire process group on timeout.

    Logs are scrubbed before persistence; inherited credentials/proxies are absent.
    Work directories must be outside the untrusted target.
    """
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        raise ValidationError('argv must be a nonempty list of strings')
    root = Path(target['root']).resolve()
    work = Path(work_dir).resolve()
    if work == root or root in work.parents:
        raise ValidationError('detector work directory must be outside target')
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    started = time.monotonic()
    buffers = [bytearray(), bytearray()]
    clipped = [False, False]
    truncated = False
    timed_out = False
    with tempfile.TemporaryDirectory(prefix='home-', dir=work) as home:
        env = {'PATH': os.environ.get('PATH', os.defpath), 'HOME': home, 'LANG':'C.UTF-8'}
        proc = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=root, env=env, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            for index, pipe in enumerate((proc.stdout, proc.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, index)
            while selector.get_map():
                if time.monotonic()-started >= timeout_s:
                    timed_out = True
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    break
                for key, _ in selector.select(min(0.1, max(0, timeout_s-(time.monotonic()-started)))):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buf = buffers[key.data]
                    remaining = max(0, max_output_bytes-len(buf))
                    buf.extend(data[:remaining])
                    truncated |= len(data)>remaining
                    clipped[key.data] |= len(data)>remaining
        proc.stdout.close(); proc.stderr.close()
        try:
            proc.wait(timeout=max(0.01, timeout_s-(time.monotonic()-started)))
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
    from .secrets import redact_text
    paths = []
    for index, (name, data) in enumerate(zip(('stdout', 'stderr'), buffers)):
        fd, filename = tempfile.mkstemp(prefix=name+'-', suffix='.log', dir=work)
        if clipped[index] or timed_out:
            # A cutoff can turn a credential into an unrecognizable fragment.
            # Discard the unfinished line before scrubbing/persisting any bytes.
            end = data.rfind(b'\n')
            data = data[:end + 1] if end >= 0 else b''
        scrubbed = redact_text(bytes(data).decode('utf-8', 'replace')).encode('utf-8')
        truncated |= len(scrubbed)>max_output_bytes
        with os.fdopen(fd, 'wb') as stream:
            stream.write(scrubbed[:max_output_bytes])
        paths.append(filename)
    return dict(stdout=paths[0], stderr=paths[1], exitCode=proc.returncode,
                status='timeout' if timed_out else 'ok', truncated=truncated,
                durationMs=int((time.monotonic()-started)*1000),
                commandDigest=sha256_hex(canonical_json(argv)))


def candidate(detector, rule, path, start=1, end=None, *, target=None, severity='medium', cwe=None, title=None):
    from .secrets import redact_text
    rule = re.sub(r'[^a-z0-9._/-]+', '-', redact_text(str(rule)).lower()).strip('-./') or 'signal'
    name = re.sub(r'[^a-z0-9._/-]+', '-', detector.lower()).strip('-./') or 'scanner'
    rule_id = name+'/'+rule
    anchor = path+'/'+rule_id
    return dict(candidateId=stable_id('cand', (target or {}).get('scanId', ''), rule_id, anchor, path, start),
                ruleId=rule_id, identity={'anchor':anchor},
                title=redact_text(title or f'Possible security issue in {path} ({name}; unconfirmed)'),
                summary=f'Unconfirmed scanner signal from {name}; requires source review.',
                evidenceState='candidate', source='detector',
                severity={'level':severity,'rationale':'Scanner severity; exploitability has not been reviewed.'},
                confidence={'level':'low','rationale':'Automated scanner signal only.'},
                taxonomy={'cwe':cwe or [],'owasp':[],'asvs':[]},
                locations=[{'path':path,'startLine':start,'endLine':end or start,'role':'signal'}],
                codeEvidence=[], proofGaps=['Scanner signal only; source-to-sink path not yet reviewed'],
                validation={'status':'NOT_RUN','level':'static','receiptIds':[]},
                provenance={'detectors':[name]}, secret=None)


class Detector:
    name = 'detector'
    kind = 'sast'
    findings_exit_codes = {0}

    def __init__(self, *, work_dir=None, **options):
        self.work_dir = work_dir
        self.options = options
        self.candidates = []
        self.parse_notes = None
        self.parse_truncated = False

    def probe(self):
        executable = shutil.which(self.name)
        result = dict(available=False, executable=executable, version=None, reason='tool not installed')
        if not executable:
            return result
        try:
            with tempfile.TemporaryDirectory() as work:
                output = safe_run([executable, '--version'], target={'root':os.getcwd()}, work_dir=work, timeout_s=10, max_output_bytes=4096)
                result.update(available=output['exitCode']==0 and output['status']=='ok',
                              version=Path(output['stdout']).read_text().strip()[:200] or None,
                              reason=None if output['exitCode']==0 else 'version probe failed')
        except (OSError, ValidationError):
            result['reason'] = 'version probe failed'
        return result

    def plan(self, target, inventory):
        return {'argv':[self.name], 'timeout_s':600, 'env':{}}

    def parse(self, raw_path):
        from .sarif import load_sarif
        return load_sarif(raw_path)

    def normalize(self, results, target, inventory):
        from .sarif import import_sarif
        candidates, receipt = import_sarif(json.dumps(results).encode(), target=target, inventory=inventory, detector_name=self.name)
        self.parse_notes = receipt['error']
        self.parse_truncated = receipt['truncated']
        if receipt['status'] != 'ok':
            raise ValueError('invalid scanner report')
        return candidates

    def run(self, target, inventory, *, timeout_s=600, work_dir=None):
        self.candidates = []
        self.parse_notes = None
        self.parse_truncated = False
        receipt = DetectorReceipt(self.name, self.kind, targetFileCount=len(inventory['files']))
        probe = self.probe()
        receipt.update(executable=probe['executable'], version=probe['version'])
        if not probe['available']:
            receipt.update(status='unavailable', error=probe['reason'])
            return receipt
        parent = Path(work_dir or self.work_dir or tempfile.gettempdir()).resolve()
        root = Path(target['root']).resolve()
        if parent == root or root in parent.parents:
            raise ValidationError('detector work directory must be outside target')
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix='detector-', dir=parent) as work:
            self._active_work = work
            plan = self.plan(target, inventory)
            if plan.get('status') == 'unavailable':
                receipt.update(status='unavailable', error=plan['reason'])
                return receipt
            argv = list(plan['argv']); argv[0] = probe['executable']
            try:
                result = safe_run(argv, target=target, work_dir=work, timeout_s=min(timeout_s, plan.get('timeout_s',600)))
                receipt.update({k:result[k] for k in ('exitCode','durationMs','commandDigest','truncated')})
                if result['status']=='timeout':
                    receipt.update(status='timeout', error='scanner timed out')
                    return receipt
                raw = plan.get('report_path', result['stdout'])
                self.candidates = self.normalize(self.parse(raw), target, inventory)
                receipt.update(resultCount=len(self.candidates), truncated=receipt['truncated'] or self.parse_truncated,
                               error=self.parse_notes, status='ok' if result['exitCode'] in self.findings_exit_codes else 'failed')
                if receipt['status']=='failed':
                    receipt['error']='scanner exited unsuccessfully'
            except OverflowError:
                receipt.update(status='parse_error', truncated=True, error='scanner report exceeds byte cap')
            except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
                receipt.update(status='parse_error', error='scanner report missing or invalid')
        return receipt
