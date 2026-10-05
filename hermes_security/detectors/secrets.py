"""Pure Python credential signals; raw credential values never leave this module."""
import json
import math
from pathlib import Path
import re
from collections import Counter
from ..canonical import secret_fingerprint, sha256_hex
from ..target.inventory import safe_read, FileRejected
from .base import Detector, DetectorReceipt, candidate
from .sarif import inventory_path

MAX_FILE_BYTES = 1024*1024
MAX_LINE_CHARS = 10000
PATTERNS = [
    ('aws-access-key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('github-token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b')),
    ('private-key', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|\Z)')),
]
ASSIGNMENT = re.compile(r'''(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)["']?\s*[:=]\s*(?:["']([^"'\r\n]{8,1000})["']|([A-Za-z0-9_!@$%^&*+./=:-]{8,1000}))''')
PLACEHOLDERS = ('example','placeholder','changeme','your_','your-','redacted','dummy','test','${','{{')


def matches(text):
    spans = []
    for kind, pattern in PATTERNS:
        spans.extend((m.start(),m.end(),kind,m.group()) for m in pattern.finditer(text))
    for m in ASSIGNMENT.finditer(text):
        group=1 if m.group(1) is not None else 2
        value=m.group(group)
        entropy=-sum((n/len(value))*math.log2(n/len(value)) for n in Counter(value).values())
        if entropy>=3 and not any(word in value.lower() for word in PLACEHOLDERS):
            spans.append((m.start(group),m.end(group),'password',value))
    # Prefer whole PEM blocks and non-overlapping matches.
    selected=[]
    for span in sorted(spans,key=lambda s:(s[0],-(s[1]-s[0]))):
        if not selected or span[0]>=selected[-1][1]:
            selected.append(span)
    return selected


def redact_text(text):
    for start,end,kind,value in reversed(matches(text)):
        text=text[:start]+f'[REDACTED:{kind}:{secret_fingerprint(value)}]'+text[end:]
    return text


def secret_candidate(name, kind, value, path, line, target, *, code=None, end=None):
    item=candidate(name,kind,path,line,end,target=target,severity='high',cwe=['CWE-798'],
                   title=f'Possible exposed credential in {path} ({name}; unconfirmed)')
    fingerprint=secret_fingerprint(value)
    item['secret']={'type':kind,'fingerprint':fingerprint}
    if code is not None:
        code=redact_text(code.replace(value,f'[REDACTED:{kind}:{fingerprint}]'))[:4000]
        item['codeEvidence']=[{'id':'ev-1','label':'Redacted credential signal','path':path,
                               'startLine':line,'endLine':end or line,'code':code,
                               'sha256':sha256_hex(code),'explanation':'Credential value removed; validity not tested.'}]
    return item


class BuiltinSecretsDetector(Detector):
    name='builtin-secrets'
    kind='secrets'

    def probe(self):
        return {'available':True,'executable':None,'version':'1','reason':None}

    def plan(self,target,inventory):
        return {'argv':[],'timeout_s':600,'env':{}}

    def parse(self,raw_path):
        raise NotImplementedError('built-in detector reads inventory directly')

    def normalize(self,results,target,inventory):
        return results

    def run(self,target,inventory,*,timeout_s=600,work_dir=None):
        import time
        started=time.monotonic()
        self.candidates=[]
        receipt=DetectorReceipt(self.name,self.kind,targetFileCount=len(inventory['files']),version='1')
        root=Path(target['root']).resolve()
        paths={e['path'] for e in inventory['files']}
        for entry in inventory['files']:
            if time.monotonic()-started>timeout_s:
                receipt.update(status='timeout',error='built-in scan timed out')
                break
            path=entry['path']
            file=root/path
            if inventory_path(file.as_uri(),target,inventory,paths=paths)!=path:
                receipt.update(status='failed', error='inventory path unavailable')
                continue
            if any(p.is_symlink() for p in [file,*file.parents] if p!=root and root in p.parents):
                receipt.update(status='failed', error='inventory path became a symlink')
                continue
            try:
                data, _ = safe_read(root, path, MAX_FILE_BYTES)
                if b'\x00' in data:
                    receipt.update(status='failed', error='binary or archive content not inspected')
                    continue
                text=data.decode('utf-8')
            except FileRejected as exc:
                if str(exc) == 'too_large':
                    receipt['truncated'] = True
                else:
                    receipt.update(status='failed', error='unsafe or changed inventory file not inspected')
                continue
            except (OSError,UnicodeError):
                receipt.update(status='failed', error='unreadable or non-UTF-8 content not inspected')
                continue
            lines=text.splitlines(keepends=True)
            if any(len(line)>MAX_LINE_CHARS for line in lines):
                receipt['truncated']=True
            # Preserve line numbers, but never scan an unbounded line.
            text=''.join(line[:MAX_LINE_CHARS].rstrip('\r\n')+'\n' for line in lines)
            for start,end,kind,value in matches(text):
                line=text.count('\n',0,start)+1
                last=line+value.count('\n')
                code='\n'.join(text.splitlines()[line-1:last])
                self.candidates.append(secret_candidate(self.name,kind,value,path,line,target,code=code,end=last))
        receipt.update(resultCount=len(self.candidates),durationMs=int((time.monotonic()-started)*1000))
        return receipt


class GitleaksDetector(Detector):
    name='gitleaks'
    kind='secrets'
    findings_exit_codes={0,1}

    def plan(self,target,inventory):
        report=str(Path(getattr(self,'_active_work',self.work_dir or '.'))/'gitleaks.json')
        return {'argv':[self.name,'detect','--no-git','--source',target['root'],'--report-format','json',
                        '--report-path',report,'--redact'],'report_path':report,'timeout_s':600,'env':{}}

    def parse(self,raw_path):
        with open(raw_path,'rb') as stream:
            data=stream.read(50*1024*1024+1)
        if len(data)>50*1024*1024:
            raise ValueError('report exceeds cap')
        results=json.loads(data)
        if not isinstance(results,list) or not all(isinstance(r,dict) for r in results):
            raise ValueError('invalid gitleaks report')
        return results

    def normalize(self,results,target,inventory):
        items=[]; dropped=0
        entries={e['path']:e for e in inventory['files']}
        local_signals={}
        self.parse_truncated=len(results)>20000
        for result in results[:20000]:
            path=inventory_path(result.get('File'),target,inventory,paths=entries)
            if path is None:
                dropped+=1
                continue
            line=result.get('StartLine',1)
            if type(line) is not int or line<1:
                raise ValueError('invalid line')
            # --redact deliberately removes the scanner secret. Recover only locally
            # from a bounded inventory file, never trust scanner match/message fields.
            if path not in local_signals:
                built=BuiltinSecretsDetector()
                built.run(target,{'files':[entries[path]]})
                local_signals[path]=built.candidates
            found=[dict(c) for c in local_signals[path] if c['locations'][0]['startLine']==line]
            for c in found:
                rebuilt = candidate(self.name,c['secret']['type'],path,line,c['locations'][0]['endLine'],target=target,
                                    severity='high',cwe=['CWE-798'],
                                    title=f'Possible exposed credential in {path} ({self.name}; unconfirmed)')
                rebuilt['secret']=c['secret']
                rebuilt['codeEvidence']=c['codeEvidence']
                c.clear(); c.update(rebuilt)
            if found:
                items.extend(found)
            else:
                raw=result.get('Secret')
                if isinstance(raw,str) and raw and raw.lower() not in ('redacted','***','[redacted]'):
                    # Never echo arbitrary scanner RuleID/Description (could embed a value).
                    code = None
                    source_file = Path(target['root'])/path
                    if not source_file.is_symlink() and source_file.stat().st_size<=MAX_FILE_BYTES:
                        source_lines = source_file.read_text(encoding='utf-8').splitlines()
                        if line<=len(source_lines) and raw in source_lines[line-1] and len(source_lines[line-1])<=MAX_LINE_CHARS:
                            code = source_lines[line-1]
                    items.append(secret_candidate(self.name,'scanner-secret',raw,path,line,target,code=code))
                else:
                    # A fingerprint of the literal word REDACTED would be fabricated
                    # evidence. Fail closed if the source cannot recover the value.
                    raise ValueError('redacted scanner signal cannot be fingerprinted from inventory')
        self.parse_notes=f'out_of_inventory: {dropped}' if dropped else None
        return items
