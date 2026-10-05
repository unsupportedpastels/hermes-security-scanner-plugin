import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from copy import deepcopy
import pytest
from hermes_security.errors import PolicyDenied, ValidationError
from hermes_security.validation.policy import check_plan, mint_grant, normalize_origin

class Store:
    def __init__(self): self.grants = {}
    def grant_validation(self, scan_id, grant):
        self.grants[grant['grantId']] = deepcopy(grant)
        return deepcopy(grant)
    def get_grant(self, grant_id): return deepcopy(self.grants[grant_id])
    def revoke_grant(self, grant_id): self.grants.pop(grant_id)

def grant():
    return dict(grantId='grt_'+'a'*24, scanId='scan', origins=['http://127.0.0.1:80'], actions=['http-probe'], expiresAt='2099-01-01T00:00:00Z', maxRequests=2, used=0)

def plan():
    return dict(scanId='scan', candidateId='c', level='active-authorized', kind='http-probe', requests=[dict(url='http://127.0.0.1/', method='GET')], cleanup={'strategy':'none-needed'}, positiveControl={'requestIndex':0,'expectedMarker':'MARK'}, negativeControl={'requestIndex':0})

@pytest.mark.parametrize('change,reason', [
    ({'grant':None}, 'missing grant'),
    ({'expiresAt':'2000-01-01T00:00:00Z'}, 'expired'),
    ({'scanId':'other'}, 'scan'),
    ({'url':'http://localhost/'}, 'origin'),
    ({'url':'file:///etc/passwd'}, 'scheme'),
    ({'url':'http://user@127.0.0.1/'}, 'userinfo'),
    ({'method':'PUT'}, 'method'), ({'method':'PATCH'}, 'method'),
    ({'method':'DELETE'}, 'method'), ({'method':'TRACE'}, 'method'),
    ({'method':'CONNECT'}, 'method'), ({'method':'POST'}, 'syntheticBody'),
    ({'used':2}, 'remaining'), ({'cleanup':None}, 'cleanup'),
    ({'negativeControl':None}, 'controls'), ({'actions':[]}, 'action'),
])
def test_denials(change, reason):
    p,g=plan(),grant()
    for k,v in change.items():
        if k=='grant': g=v
        elif k in {'expiresAt','scanId','used','actions'}: g[k]=v
        elif k in {'url','method'}: p['requests'][0][k]=v
        else: p[k]=v
    with pytest.raises(PolicyDenied,match=reason): check_plan(p,grant=g,safety_level='active-authorized',now='2026-01-01T00:00:00Z')

def test_grant_and_origin():
    s=Store()
    g=mint_grant(s,'scan',origins=['HTTPS://Example.COM/path'],actions=['http-probe'],expires_in_s=60,max_requests=2)
    assert g['origins']==['https://example.com:443'] and g['used']==0
    assert s.get_grant(g['grantId'])==g
    assert normalize_origin('http://[::1]/')=='http://[::1]:80'
    with pytest.raises(ValidationError): mint_grant(s,'scan',origins=[],actions=['shell'],expires_in_s=0,max_requests=0)
    with pytest.raises(PolicyDenied): mint_grant(s,'scan',origins=[],actions=['local-command'],expires_in_s=60,max_requests=2,created_by='agent')

@pytest.mark.parametrize('argv', ['echo x; curl x', ['curl','https://example.com'], ['env','wget','x'], ['sh','-c','echo x']])
def test_command_denial(argv):
    p=dict(kind='local-command',level='local-safe',commands=[argv],cleanup={'strategy':'copy'},positiveControl={'commandIndex':0,'expectedMarker':'x'},negativeControl={'commandIndex':0})
    with pytest.raises(PolicyDenied): check_plan(p,grant=None,safety_level='local-safe',now='2026-01-01T00:00:00Z')

def test_static_denies_execution():
    p=plan();p['kind']='local-command'
    with pytest.raises(PolicyDenied,match='static'): check_plan(p,grant=None,safety_level='static',now='2026-01-01T00:00:00Z')
