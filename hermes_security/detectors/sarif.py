"""Defensive SARIF 2.1.0 ingestion. Scanner evidence never proves a finding."""
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import unquote, urlsplit
from .base import DetectorReceipt, candidate

MAX_BYTES = 50 * 1024 * 1024
MAX_RESULTS = 20000


def load_sarif(source):
    if isinstance(source, (bytes, bytearray)):
        data = source
    else:
        with open(source, 'rb') as stream:
            data = stream.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES:
        raise OverflowError('report exceeds input cap')
    doc = json.loads(data)
    if not isinstance(doc, dict) or doc.get('version')!='2.1.0' or not isinstance(doc.get('runs'),list) or not doc['runs']:
        raise ValueError('invalid SARIF')
    return doc


def inventory_path(uri, target, inventory, *, paths=None):
    if not isinstance(uri, str) or '\x00' in uri or '\\' in uri:
        return None
    parsed = urlsplit(uri)
    if parsed.scheme not in ('','file') or parsed.netloc not in ('','localhost') or parsed.query or parsed.fragment:
        return None
    value = unquote(parsed.path)
    if '\x00' in value or '\\' in value or '..' in PurePosixPath(value).parts:
        return None
    root = Path(target['root']).resolve()
    path = Path(value)
    resolved = (root/path).resolve()
    try:
        rel = resolved.relative_to(root).as_posix()
    except ValueError:
        return None
    return rel if rel in (paths if paths is not None else {entry['path'] for entry in inventory['files']}) else None


def import_sarif(path_or_bytes, *, target, inventory, detector_name='sarif'):
    receipt = DetectorReceipt(detector_name, targetFileCount=len(inventory['files']))
    candidates = []
    entries = {e['path']:e for e in inventory['files']}
    dropped = 0
    seen = 0
    try:
        doc = load_sarif(path_or_bytes)
        for run in doc['runs']:
            if not isinstance(run,dict) or not isinstance(run.get('results'),list):
                raise ValueError('invalid results')
            rules = run.get('tool',{}).get('driver',{}).get('rules',[])
            if not isinstance(rules,list):
                raise ValueError('invalid rules')
            rules = {str(r.get('id')):r for r in rules if isinstance(r,dict)}
            for result in run['results']:
                seen += 1
                if seen>MAX_RESULTS:
                    receipt['truncated']=True
                    break
                if not isinstance(result,dict) or not isinstance(result.get('message'),dict):
                    raise ValueError('invalid result')
                rule_id = result.get('ruleId','unknown')
                rule = rules.get(str(rule_id),{})
                props = rule.get('properties',{})
                if not isinstance(props,dict):
                    raise ValueError('invalid rule properties')
                cwes = sorted(set('CWE-'+m.group(1) for tag in props.get('tags',[]) if isinstance(tag,str) for m in [re.search(r'cwe-(\d+)',tag,re.I)] if m))
                severity = {'error':'high','warning':'medium','note':'low','none':'informational'}.get(result.get('level','warning'),'medium')
                try:
                    score = float(props.get('security-severity',result.get('properties',{}).get('security-severity')))
                    severity = 'critical' if score>=9 else 'high' if score>=7 else 'medium' if score>=4 else 'low'
                except (ValueError,TypeError):
                    pass
                locations = result.get('locations',[])
                if not isinstance(locations,list):
                    raise ValueError('invalid locations')
                valid = []
                for loc in locations:
                    physical = loc.get('physicalLocation',{})
                    artifact = physical.get('artifactLocation',{})
                    # uriBaseId and artifact indexes cannot silently escape inventory scope.
                    path = inventory_path(artifact.get('uri'), target, inventory, paths=entries)
                    if path is None:
                        dropped += 1
                        continue
                    region = physical.get('region',{})
                    start, end = region.get('startLine',1), region.get('endLine',region.get('startLine',1))
                    if type(start) is not int or type(end) is not int or start<1 or end<start:
                        raise ValueError('invalid line range')
                    entry = entries[path]
                    if entry.get('lines') is not None and end>entry['lines']:
                        dropped += 1
                        continue
                    valid.append((path,start,end))
                if not valid:
                    continue
                path,start,end = valid[0]
                # Map message meaning to a controlled label, never echo scanner
                # snippets/messages verbatim: they may embed arbitrary credentials.
                message = result['message'].get('text', result['message'].get('markdown', ''))
                if not isinstance(message, str):
                    raise ValueError('invalid message')
                topic = 'SQL injection' if 'CWE-89' in cwes or 'sql injection' in message.lower() else 'security issue'
                item = candidate(detector_name,rule_id,path,start,end,target=target,severity=severity,cwe=cwes,
                                 title=f'Possible {topic} in {path} ({detector_name}; unconfirmed)')
                item['locations']=[{'path':p,'startLine':s,'endLine':e,'role':'signal'} for p,s,e in valid]
                candidates.append(item)
            if receipt['truncated']:
                break
    except OverflowError:
        receipt.update(status='parse_error', truncated=True, error='SARIF input exceeds byte cap')
        candidates=[]
    except (ValueError,TypeError,KeyError,AttributeError,OSError,RecursionError):
        receipt.update(status='parse_error',error='invalid SARIF report')
        candidates=[]
    if dropped:
        receipt['error'] = f'out_of_inventory: {dropped}'
    receipt['resultCount']=len(candidates)
    return candidates,receipt
