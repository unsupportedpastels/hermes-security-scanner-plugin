import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import json
from hermes_security.detectors.sarif import import_sarif


def report(uri='src/a%20b.py'):
    return {'version':'2.1.0','runs':[{'tool':{'driver':{'name':'Example','rules':[{'id':'SQL.Test','properties':{'tags':['external/cwe/cwe-89'],'security-severity':'8.1'}}]}},'results':[{'ruleId':'SQL.Test','level':'warning','message':{'text':'SQL injection'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':uri},'region':{'startLine':2,'endLine':3}}}]}]}]}


def test_sarif_contract(tmp_path):
    inv={'files':[{'path':'src/a b.py','lines':4}]}
    candidates, receipt=import_sarif(json.dumps(report()).encode(),target={'root':str(tmp_path)},inventory=inv,detector_name='semgrep')
    assert receipt['status']=='ok'
    c=candidates[0]
    assert c['ruleId']=='semgrep/sql.test'
    assert c['taxonomy']['cwe']==['CWE-89']
    assert c['severity']['level']=='high'
    assert c['evidenceState']=='candidate'
    assert c['locations'][0]['path']=='src/a b.py'
    for uri in ['../escape.py','file:///etc/passwd','https://host/src/a%20b.py']:
        cs,r=import_sarif(json.dumps(report(uri)).encode(),target={'root':str(tmp_path)},inventory=inv)
        assert not cs and 'out_of_inventory' in r['error']


def test_fixture_and_local_file_uri(tmp_path):
    target={'root':str(tmp_path)}
    inv={'files':[{'path':'src/db query.py','lines':4}]}
    fixture=Path(__file__).parents[1]/'fixtures/detectors/semgrep.sarif'
    cs,r=import_sarif(fixture,target=target,inventory=inv,detector_name='semgrep')
    assert r['resultCount']==1 and cs[0]['taxonomy']['cwe']==['CWE-89']
    data=json.loads(fixture.read_text())
    data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']=(tmp_path/'src/db query.py').as_uri()
    assert import_sarif(json.dumps(data).encode(),target=target,inventory=inv)[1]['resultCount']==1


def test_invalid_and_truncated(tmp_path, monkeypatch):
    import hermes_security.detectors.sarif as s
    kwargs={'target':{'root':str(tmp_path)},'inventory':{'files':[{'path':'src/a b.py','lines':4}]}}
    assert import_sarif(b'',**kwargs)[1]['status']=='parse_error'
    monkeypatch.setattr(s,'MAX_RESULTS',1)
    data=report();data['runs'][0]['results']*=2
    cs,r=import_sarif(json.dumps(data).encode(),**kwargs)
    assert len(cs)==1 and r['truncated']
    monkeypatch.setattr(s,'MAX_BYTES',10)
    assert import_sarif(json.dumps(data).encode(),**kwargs)[1]['truncated']
