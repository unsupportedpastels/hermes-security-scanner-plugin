"""OSV scanner adapter. Offline support must be explicitly configured."""
import json
from .base import Detector, candidate
from .sarif import inventory_path
from .secrets import redact_text

class OSVScannerDetector(Detector):
    name='osv-scanner'
    kind='sca'
    findings_exit_codes={0,1}

    def plan(self,target,inventory):
        # Version-dependent offline databases/flags must be selected by the caller.
        flags=self.options.get('offline_flags')
        if not isinstance(flags,list) or not flags or not all(isinstance(f,str) for f in flags):
            return {'argv':[],'timeout_s':600,'env':{},'status':'unavailable','reason':'no supported offline OSV database/flags configured'}
        return {'argv':[self.name,'--format','json',*flags,'-r',target['root']],'timeout_s':600,'env':{}}

    def parse(self,raw_path):
        with open(raw_path,'rb') as stream:
            data=stream.read(50*1024*1024+1)
        if len(data)>50*1024*1024:
            raise ValueError('OSV report exceeds cap')
        report=json.loads(data)
        if not isinstance(report,dict) or not isinstance(report.get('results'),list):
            raise ValueError('invalid OSV report')
        return report['results']

    def normalize(self,results,target,inventory):
        items=[]; dropped=0
        paths={e['path'] for e in inventory['files']}
        for group in results:
            path=inventory_path(group.get('source',{}).get('path'),target,inventory,paths=paths)
            if path is None:
                dropped+=1
                continue
            for package in group.get('packages',[]):
                info=package.get('package',{})
                for vuln in package.get('vulnerabilities',[]):
                    if len(items)>=20000:
                        self.parse_truncated=True
                        return items
                    advisory=redact_text(str(vuln['id']))[:200]
                    item=candidate(self.name,advisory,path,target=target)
                    item['taxonomy']['owasp']=['A03:2025']
                    item['dependency']={'package':redact_text(str(info.get('name','')))[:200],
                        'version':redact_text(str(info.get('version','')))[:200], 'advisoryIds':[advisory]}
                    item['title']=f'Possible vulnerable dependency in {path} (osv-scanner; unconfirmed)'
                    items.append(item)
        self.parse_notes=f'out_of_inventory: {dropped}' if dropped else None
        return items
