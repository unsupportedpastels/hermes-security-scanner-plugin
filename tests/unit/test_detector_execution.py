import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
import json
import os
import pytest
from hermes_security.detectors import run_detectors
from hermes_security.detectors.base import safe_run, DetectorReceipt
from hermes_security.detectors.secrets import BuiltinSecretsDetector, GitleaksDetector, redact_text
from hermes_security.detectors.semgrep import SemgrepDetector
from hermes_security.detectors.dependencies import OSVScannerDetector
from hermes_security.detectors.iac import TrivyDetector, CheckovDetector


def setup_target(tmp_path,text='x\n'):
    root=tmp_path/'target'; root.mkdir()
    (root/'a.py').write_text(text)
    return {'root':str(root)}, {'files':[{'path':'a.py','lines':len(text.splitlines()),'size':len(text)}]}


def test_builtin_never_serializes_values(tmp_path):
    values=['AKIAABCDEFGHIJKLMNOP','ghp_'+'Ab2Cd3Ef4Gh5Ij6Kl7Mn8Op9','v3ry$C0mpl3x!P4ss',
            '-----BEGIN PRIVATE KEY-----\nYXNkZmdoamtsMTIzNDU2Nzg5\n-----END PRIVATE KEY-----']
    text='key = "'+values[0]+'"\ntoken = "'+values[1]+'"\npassword = "'+values[2]+'"\n'+values[3]+'\npassword = ""\npassword = "your_password_here"\n'
    target,inv=setup_target(tmp_path,text)
    d=BuiltinSecretsDetector(); r=d.run(target,inv)
    assert r['resultCount']==4
    serialized=json.dumps([d.candidates,r])
    for value in values:
        assert value not in serialized
        assert value not in redact_text(text)
    assert 'YXNkZmdoamtsMTIzNDU2Nzg5' not in serialized
    assert all(c['secret']['fingerprint'].startswith('sha256:') for c in d.candidates)
    cs,rs=run_detectors(['builtin-secrets','unknown'],target,inv,tmp_path/'work')
    assert len(cs)==4 and rs[1]['status']=='unavailable'


def test_unquoted_and_json_secret_redaction(tmp_path):
    value='K9z+L3m$P8r!Q2sV'
    target,inv=setup_target(tmp_path,'password='+value+'\n')
    d=BuiltinSecretsDetector(); assert d.run(target,inv)['resultCount']==1
    assert value not in json.dumps(d.candidates)
    assert value not in redact_text(json.dumps({'password':value}))


def test_redacted_gitleaks_recovers_real_fingerprint(tmp_path):
    value='AKIAABCDEFGHIJKLMNOP'
    target,inv=setup_target(tmp_path,'key = "'+value+'"\n')
    d=GitleaksDetector()
    cs=d.normalize([{'File':'a.py','StartLine':1,'Secret':'REDACTED'}],target,inv)
    from hermes_security.canonical import secret_fingerprint
    assert cs[0]['secret']['fingerprint']==secret_fingerprint(value)
    assert cs[0]['ruleId'].startswith('gitleaks/')
    assert value not in json.dumps(cs)
    with pytest.raises(ValueError):
        d.normalize([{'File':'a.py','StartLine':2,'Secret':'REDACTED'}],target,inv)


def test_caps_and_binary(tmp_path):
    target,inv=setup_target(tmp_path,'x'*11000+'\n')
    d=BuiltinSecretsDetector(); assert d.run(target,inv)['truncated']
    Path(target['root'],'a.py').write_bytes(b'x'*(1024*1024+1))
    assert d.run(target,inv)['truncated']
    Path(target['root'],'a.py').write_bytes(b'\0AKIAABCDEFGHIJKLMNOP')
    assert d.run(target,inv)['resultCount']==0


def executable(tmp_path,name,body):
    directory=tmp_path/'bin';directory.mkdir(exist_ok=True)
    path=directory/name
    path.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then printf "scanner 1\\n"; exit 0; fi\n'+body)
    path.chmod(0o700)
    return directory


@pytest.mark.parametrize('name',['semgrep','gitleaks'])
@pytest.mark.parametrize('mode,expected',[('timeout','timeout'),('empty','parse_error'),('findings','ok'),('badexit','failed'),('absent','unavailable')])
def test_fake_scanners(tmp_path,monkeypatch,name,mode,expected):
    target,inv=setup_target(tmp_path)
    sarif=json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'fake'}},'results':[]}]})
    if mode=='timeout': body='/bin/sleep 10\n'
    elif mode=='empty': body='exit 0\n'
    elif name=='semgrep': body="printf '%s' '"+sarif+"'\nexit "+('2' if mode=='badexit' else '1')+'\n'
    else: body='while [ "$1" != "--report-path" ]; do shift; done\nshift\nprintf "[]" > "$1"\nexit '+('2' if mode=='badexit' else '1')+'\n'
    binpath=executable(tmp_path,name,body)
    if mode=='absent': (binpath/name).unlink()
    monkeypatch.setenv('PATH',str(binpath))
    work=tmp_path/'work';work.mkdir()
    d=SemgrepDetector(work_dir=work,config='explicit-rule.yml') if name=='semgrep' else GitleaksDetector(work_dir=work)
    receipt=d.run(target,inv,timeout_s=.15)
    assert receipt['status']==expected
    assert not list(work.iterdir())


def test_runner_caps_env_digest(tmp_path,monkeypatch):
    target,inv=setup_target(tmp_path)
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY','never-inherited')
    command=[sys.executable,'-c','import os; print(os.environ); print("x"*20000)']
    result=safe_run(command,target=target,work_dir=tmp_path/'work',max_output_bytes=1000)
    assert result['truncated']
    assert Path(result['stdout']).stat().st_size<=1000
    assert 'never-inherited' not in Path(result['stdout']).read_text()
    from hermes_security.canonical import canonical_json,sha256_hex
    assert result['commandDigest']==sha256_hex(canonical_json(command))


def test_plans_and_osv_parse(tmp_path):
    target,inv=setup_target(tmp_path)
    assert SemgrepDetector().plan(target,inv)['reason']=='no offline ruleset configured'
    assert OSVScannerDetector().plan(target,inv)['status']=='unavailable'
    assert '--skip-check-update' in TrivyDetector().plan(target,inv)['argv']
    assert '--skip-download' in CheckovDetector().plan(target,inv)['argv']
    d=OSVScannerDetector(offline_flags=['--offline'])
    assert '--offline' in d.plan(target,inv)['argv']
    raw=tmp_path/'osv.json'
    raw.write_text(json.dumps({'results':[{'source':{'path':'a.py'},'packages':[{'package':{'name':'foo','version':'1'},'vulnerabilities':[{'id':'GHSA-abcd-1234-5678'}]}]}]}))
    cs=d.normalize(d.parse(raw),target,inv)
    assert cs[0]['taxonomy']['owasp']==['A03:2025']
    assert cs[0]['dependency']['package']=='foo'


def test_gitleaks_json_redaction(tmp_path):
    target,inv=setup_target(tmp_path)
    secret='another$Unusual+Credential-938'
    raw=tmp_path/'g.json'; raw.write_text(json.dumps([{'File':'a.py','StartLine':1,'Secret':secret,'Match':secret,'Description':secret}]))
    d=GitleaksDetector()
    cs=d.normalize(d.parse(raw),target,inv)
    assert secret not in json.dumps(cs)
    assert cs[0]['secret']['type']=='scanner-secret'


@pytest.mark.parametrize('tool',['semgrep','gitleaks','osv-scanner','trivy','checkov'])
def test_real_probe_if_installed(tool):
    import shutil
    from hermes_security.detectors import REGISTRY
    if not shutil.which(tool): pytest.skip('optional binary not installed')
    assert REGISTRY[tool]().probe()['available']
