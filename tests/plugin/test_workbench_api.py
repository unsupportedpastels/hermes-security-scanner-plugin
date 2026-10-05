"""Real profile-local workbench HTTP acceptance; no live Hermes required."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
PREFIX = '/api/plugins/hermes-security'


@pytest.fixture
def api(tmp_path, monkeypatch):
    import types
    # Never import/start the real gateway transport during offline tests, even
    # when earlier host-parser tests have added the Hermes source to sys.path.
    monkeypatch.setitem(sys.modules, 'hermes_cli.plugin_events', types.SimpleNamespace(broadcast_plugin_event=lambda *args: None))
    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'profile'))
    monkeypatch.chdir('/')
    spec = importlib.util.spec_from_file_location('test_security_dashboard', ROOT / 'dashboard/plugin_api.py')
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    app = FastAPI()
    app.include_router(module.router, prefix=PREFIX)
    with TestClient(app) as client:
        yield module, client


def test_standalone_health_and_real_scan(api, tmp_path):
    module, client = api
    assert client.get(PREFIX + '/health').json() == {'ok': True, 'plugin': 'hermes-security'}
    root = tmp_path / 'repo'; root.mkdir()
    (root / 'app.py').write_text('print("not executed")\n')
    response = client.post(PREFIX + '/scans', json={'path': str(root)})
    assert response.status_code == 200, response.text
    scan = response.json()
    assert scan['status'] == 'awaiting_analysis'
    assert client.get(PREFIX + '/scans/' + scan['scanId']).json() == scan
    assert client.get(PREFIX + '/summary').json()['scans'] == 1


@pytest.fixture
def populated(api, tmp_path):
    module, client = api
    root = tmp_path / 'repo'; root.mkdir()
    secret = 'AKIA' + 'Q7X2M9P4R8S6T1V3'
    (root / 'app.py').write_text('def get_invoice(invoice_id):\n    return invoices.get(invoice_id)\nAWS_ACCESS_KEY_ID = "' + secret + '"\n')
    # Import a real acceptance helper by file path (tests need not be packages).
    spec = importlib.util.spec_from_file_location('security_acceptance_helpers', ROOT / 'tests/integration/test_end_to_end_static.py')
    helpers = importlib.util.module_from_spec(spec); spec.loader.exec_module(helpers)
    service = module.get_service()
    plan = service.start_scan(path=str(root))
    candidate = helpers.candidate_for(root)
    candidate['evidenceState'] = 'source_supported'
    service.submit_worker_result(helpers.worker(plan, [candidate]))
    service.run_detectors(plan['scanId'], ['builtin-secrets'])
    service.finalize(plan['scanId'])
    fid = service.list_findings()['items'][0]['finding_id']
    return module, client, root, plan['scanId'], fid, secret


def test_scan_rows_carry_counts_only_after_seal(populated, tmp_path):
    module, client, root, sid, fid, secret = populated
    rows = {r['scan_id']: r for r in client.get(PREFIX + '/scans').json()['items']}
    indexed = [f for f in client.get(PREFIX + '/findings').json()['items'] if f['scan_id'] == sid]
    assert indexed
    expected = {}
    for f in indexed:
        expected[f['severity']] = expected.get(f['severity'], 0) + 1
    assert rows[sid]['counts'] == expected
    open_sid = client.post(PREFIX + '/scans', json={'path': str(root)}).json()['scanId']
    rows = {r['scan_id']: r for r in client.get(PREFIX + '/scans').json()['items']}
    assert rows[open_sid]['counts'] is None


def test_all_reads_triage_and_exports(populated):
    module, client, root, sid, fid, secret = populated
    paths = ['/health', '/summary', '/scans', '/scans/' + sid,
             '/scans/' + sid + '/activity', '/scans/' + sid + '/coverage',
             '/findings', '/findings/' + fid, '/findings/' + fid + '/patch', '/repositories']
    paths += ['/scans/' + sid + '?section=' + s for s in ['inventory', 'workers', 'detectors', 'validations', 'candidates', 'findings', 'chains', 'coverage', 'activity', 'manifest', 'report']]
    for path in paths:
        response = client.get(PREFIX + path)
        assert response.status_code == 200, (path, response.text)
        assert secret not in response.text
    assert client.get(PREFIX + '/findings/' + fid + '/patch').json()['readOnly'] is True
    for state in ['closed', 'accepted_risk', 'false_positive', 'open']:
        response = client.post(PREFIX + '/findings/' + fid + '/triage', json={'state': state, 'note': 'Reviewed locally.'})
        assert response.status_code == 200
        assert response.json()['triage']['state'] == state
        assert response.json() == client.get(PREFIX + '/findings/' + fid).json()
        assert secret not in response.text
    for fmt in ['md', 'sarif', 'json', 'csv']:
        expected = module.get_service().export(sid, fmt)
        response = client.get(PREFIX + '/exports/' + sid + '/' + fmt)
        assert response.status_code == 200
        assert response.headers['content-type'].startswith('application/json')
        assert response.json() == expected
        response = client.get(PREFIX + '/exports/' + sid + '/' + fmt + '?download=1')
        assert response.status_code == 200
        assert response.text == expected['content']
        assert expected['filename'] in response.headers['content-disposition']
        assert response.headers['content-type'].startswith(expected['contentType'])
        assert response.headers['content-disposition'] == 'attachment; filename="' + expected['filename'] + '"'
        assert secret not in response.text


def test_scan_actions_policy_and_events(api, tmp_path, monkeypatch):
    import types
    module, client = api
    events = []
    monkeypatch.setitem(sys.modules, 'hermes_cli.plugin_events', types.SimpleNamespace(broadcast_plugin_event=lambda *args: events.append(args)))
    root = tmp_path / 'repo'; root.mkdir(); (root / 'a.py').write_text('x = 1\n')
    response = client.post(PREFIX + '/scans', json={'path': str(root), 'safety_level': 'local-safe'})
    assert response.status_code == 403 and not events
    response = client.post(PREFIX + '/scans', json={'path': str(root), 'safety_level': 'local-safe', 'allowLocalValidation': True})
    assert response.status_code == 200
    sid = response.json()['scanId']
    for action, status in [('cancel', 'canceled'), ('resume', 'awaiting_analysis')]:
        response = client.post(PREFIX + '/scans/' + sid + '/' + action)
        assert response.status_code == 200
        assert response.json()['status'] == status
        assert response.json() == client.get(PREFIX + '/scans/' + sid).json()
    assert events == [('hermes-security', 'scan.updated', {'scanId': sid})] * 3
    rows = client.get(PREFIX + '/scans/' + sid + '/activity', params={'limit': 1}).json()['items']
    assert len(rows) == 1
    after = rows[0]['id']
    assert all(r['id'] > after for r in client.get(PREFIX + '/scans/' + sid + '/activity', params={'after_id': after}).json()['items'])
    def broken(*args):
        raise RuntimeError('no transport')
    monkeypatch.setitem(sys.modules, 'hermes_cli.plugin_events', types.SimpleNamespace(broadcast_plugin_event=broken))
    assert client.post(PREFIX + '/scans/' + sid + '/cancel').status_code == 200


def test_sql_filters_and_pagination(populated):
    module, client, root, sid, fid, secret = populated
    service = module.get_service()
    for mode in ['standard', 'deep', 'deep']:
        service.start_scan(path=str(root), mode=mode)
    response = client.get(PREFIX + '/scans', params={'q': str(root), 'mode': 'deep', 'status': 'awaiting_analysis', 'limit': 1, 'offset': 1}).json()
    assert response['total'] == 2 and len(response['items']) == 1
    assert response['items'][0]['mode'] == 'deep'
    assert client.get(PREFIX + '/scans', params={'mode': 'deep', 'offset': 2}).json() == {'items': [], 'total': 2}
    row = service.list_findings()['items'][0]
    filters = {'q': row['title'], 'severity': row['severity'], 'evidenceState': row['evidence_state'],
               'validationLevel': 'static', 'repo': row['repo_key'], 'owasp': row['owasp'][0],
               'source': 'worker', 'chained': 'false', 'status': 'open'}
    for key, value in filters.items():
        result = client.get(PREFIX + '/findings', params={key: value, 'limit': 1}).json()
        assert result['total'] == 1 and len(result['items']) == 1, (key, result)
        assert 'data' not in result['items'][0] and 'codeEvidence' not in result['items'][0]
        missing = 'true' if key == 'chained' else 'does-not-match'
        assert client.get(PREFIX + '/findings', params={key: missing}).json()['total'] == 0
    assert client.get(PREFIX + '/findings', params={**filters, 'offset': 1}).json() == {'items': [], 'total': 1}
    assert client.get(PREFIX + '/findings', params={**filters, 'limit': 0}).json() == {'items': [], 'total': 1}
    assert client.get(PREFIX + '/repositories', params={'offset': 1}).json() == {'items': [], 'total': 1}
    assert client.get(PREFIX + '/scans/' + sid, params={'section': 'findings', 'offset': 1}).json() == {'items': [], 'total': 1}


@pytest.mark.parametrize('path', ['/scans?limit=101', '/findings?offset=-1', '/repositories?limit=101', '/scans/x?limit=101', '/scans/x/activity?limit=501', '/scans/x/activity?after_id=-1', '/findings?chained=nonsense'])
def test_bad_query_is_sanitized_400(api, path):
    _, client = api
    response = client.get(PREFIX + path)
    assert response.status_code == 400
    assert response.json() == {'error': {'code': 'invalid_input', 'message': 'Invalid request.'}}


def test_error_mapping_and_no_authority_routes(populated, monkeypatch):
    module, client, root, sid, fid, secret = populated
    for path in ['/scans/missing', '/findings/missing', '/scans/missing/activity', '/scans/missing/coverage']:
        assert client.get(PREFIX + path).status_code == 404
    assert client.post(PREFIX + '/scans/' + sid + '/cancel').status_code == 409
    assert client.post(PREFIX + '/scans/' + sid + '/resume').status_code == 409
    assert client.get(PREFIX + '/exports/' + sid + '/bad').status_code == 400
    assert client.get(PREFIX + '/scans/' + sid + '?section=bad').status_code == 400
    assert client.post(PREFIX + '/findings/' + fid + '/triage', json={'state': 'invented'}).status_code == 400
    assert client.post(PREFIX + '/findings/' + fid + '/triage', json={'state': 'open', 'extra': 1}).status_code == 400
    for body in [{}, [], {'path': str(root), 'unexpected': True}]:
        assert client.post(PREFIX + '/scans', json=body).status_code == 400
    assert client.post(PREFIX + '/scans', content='{broken', headers={'Content-Type': 'application/json'}).status_code == 400
    assert client.post(PREFIX + '/scans', content='x' * (module.MAX_JSON_BYTES + 1)).status_code == 400
    for suffix in ['grants', 'mint_grant', 'record_validations', 'validations']:
        assert client.post(PREFIX + '/scans/' + sid + '/' + suffix, json={}).status_code == 404
    def fail():
        raise RuntimeError('/private/file ' + secret)
    monkeypatch.setattr(module.get_service(), 'summary', fail)
    response = client.get(PREFIX + '/summary')
    assert response.status_code == 500 and secret not in response.text and '/private' not in response.text
    for code, status in [('invalid_input', 400), ('not_found', 404), ('conflict', 409), ('sealed', 409), ('policy_denied', 403), ('target_error', 500)]:
        def fail(code=code):
            raise module.SecurityError('/private/file ' + secret, code=code)
        monkeypatch.setattr(module.get_service(), 'summary', fail)
        response = client.get(PREFIX + '/summary')
        assert response.status_code == status and secret not in response.text and '/private' not in response.text


def test_profile_isolation(api, tmp_path, monkeypatch):
    module, client = api
    first = module.get_service()
    root = tmp_path / 'repo'; root.mkdir(); (root / 'a.py').write_text('x=1\n')
    sid = client.post(PREFIX + '/scans', json={'path': str(root)}).json()['scanId']
    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'profiles' / 'second'))
    assert client.get(PREFIX + '/summary').json()['scans'] == 0
    assert client.get(PREFIX + '/summary').json()['profile'] == 'second'
    assert client.get(PREFIX + '/scans/' + sid).status_code == 404
    assert module.get_service() is not first
    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'profile'))
    assert module.get_service() is first
    assert client.get(PREFIX + '/scans/' + sid).status_code == 200


def test_triage_event_and_output_bound(populated, monkeypatch):
    import types
    module, client, root, sid, fid, secret = populated
    events = []
    monkeypatch.setitem(sys.modules, 'hermes_cli.plugin_events', types.SimpleNamespace(broadcast_plugin_event=lambda *args: events.append(args)))
    assert client.post(PREFIX + '/findings/' + fid + '/triage', json={'state': 'closed'}).status_code == 200
    assert events == [('hermes-security', 'finding.updated', {'findingId': fid})]
    monkeypatch.setattr(module.get_service(), 'summary', lambda: {'tooLarge': 'a' * module.MAX_JSON_BYTES})
    assert client.get(PREFIX + '/summary').status_code == 500


def test_sql_trace_filters_precede_limit(populated, monkeypatch):
    from contextlib import contextmanager
    module, client, root, sid, fid, secret = populated
    service = module.get_service()
    queries = []
    original = service.store._connection
    @contextmanager
    def traced():
        with original() as conn:
            conn.set_trace_callback(queries.append)
            yield conn
    monkeypatch.setattr(service.store, '_connection', traced)
    response = client.get(PREFIX + '/findings', params={'validationLevel': 'static', 'source': 'worker', 'limit': 1, 'offset': 1})
    assert response.json() == {'items': [], 'total': 1}
    query = next(q for q in queries if 'ORDER BY f.rowid DESC LIMIT 1 OFFSET 1' in q)
    assert "json_extract(f.data,'$.validation.level')='static'" in query
    assert "'worker'='worker'" in query
    assert ',f.data,' not in query.split(' FROM findings')[0]
    assert not query.startswith('SELECT f.data')
    queries.clear()
    client.get(PREFIX + '/scans', params={'mode': 'deep', 'status': 'awaiting_analysis', 'limit': 1, 'offset': 1})
    query = next(q for q in queries if 'ORDER BY rowid DESC LIMIT 1 OFFSET 1' in q)
    assert "mode='deep'" in query and "status='awaiting_analysis'" in query


def test_isolated_import_without_repo_on_sys_path(tmp_path):
    import os
    import subprocess
    code = '''import importlib.util, sys
spec = importlib.util.spec_from_file_location('standalone_dashboard', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert module.SecurityService.__module__.startswith('_hermes_security_dashboard_')
assert module.get_service().summary()['scans'] == 0
print(module.health())
'''
    result = subprocess.run([sys.executable, '-I', '-c', code, str(ROOT / 'dashboard/plugin_api.py')],
                            cwd='/', env={**os.environ, 'HERMES_HOME': str(tmp_path / 'isolated')},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "'plugin': 'hermes-security'" in result.stdout


def test_manifest_contract():
    manifest = json.loads((ROOT / 'dashboard/manifest.json').read_text())
    assert manifest['name'] == 'hermes-security' and manifest['api'] == 'plugin_api.py'
