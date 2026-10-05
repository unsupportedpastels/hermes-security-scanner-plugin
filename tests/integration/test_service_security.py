"""Hostile payload and provenance boundaries at the public service layer."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from hermes_security.errors import SecurityError, ValidationError, Conflict, PolicyDenied
from hermes_security.service import SecurityService
from hermes_security.validation import build_receipt, static_receipt
from hermes_security.orchestration.reducer import reduce_candidates
from test_service_modes import setup
from test_end_to_end_static import candidate_for, worker


@pytest.mark.parametrize('change', [
    {'locations': [{'path': '../outside.py', 'startLine': 1}]},
    {'locations': [{'path': 'app.py', 'startLine': 100}]},
    {'codeEvidence': [{}]},
    {'validation': {'status': 'passed', 'level': 'local-safe', 'receiptIds': []}},
    {'summary': 'AKIA' + 'Q7X2M9P4R8S6T1V3'},
])
def test_reject_candidate_citations_claims_and_secrets(tmp_path, change):
    root, service, plan = setup(tmp_path)
    candidate = candidate_for(root); candidate.update(change)
    result = service.submit_worker_result(worker(plan, [candidate]))
    assert result['inserted'] == 0 and result['rejected']
    assert service.get_scan(plan['scanId'], 'candidates')['total'] == 0
    assert 'Q7X2M9' not in json.dumps(result)


def test_packet_scan_and_attempt_binding(tmp_path):
    root, service, plan = setup(tmp_path)
    candidate = candidate_for(root)
    payload = worker(plan, [candidate])
    result = service.submit_worker_result(payload)
    assert result['inserted'] == 1
    altered = deepcopy(payload); altered['notes'] = 'changed result'
    with pytest.raises(Conflict): service.submit_worker_result(altered)
    bad = dict(payload, attemptId='att_other', packetId='pkt_' + '0' * 24)
    with pytest.raises(ValidationError): service.submit_worker_result(bad)
    bad = dict(payload, attemptId='att_other', snapshotDigest='sha256:' + '0' * 64)
    with pytest.raises(Conflict): service.submit_worker_result(bad)
    with pytest.raises(ValidationError): service.submit_worker_result({**payload, 'extra': True})
    with pytest.raises(ValidationError): service.submit_worker_result({**payload, 'notes': float('nan')})


def test_runtime_receipt_cannot_be_forged_by_worker_or_tool(tmp_path):
    root, service, plan = setup(tmp_path)
    service.submit_worker_result(worker(plan, [candidate_for(root)]))
    candidate = service.get_scan(plan['scanId'], 'candidates')['items'][0]
    positive = {'ran': True, 'matched': True, 'complete': True}
    negative = {'ran': True, 'matched': False, 'complete': True}
    receipt = build_receipt({'candidateId': candidate['candidateId'], 'level': 'local-safe', 'kind': 'local-command'}, status='passed', positive=positive, negative=negative)
    with pytest.raises(PolicyDenied): service.record_validations(plan['scanId'], receipts=[receipt])
    assert service.store.validations(plan['scanId']) == []
    static = static_receipt(candidate, checks={k: True for k in ('source', 'control', 'sink', 'boundary', 'counterevidence')})
    service.record_validations(plan['scanId'], receipts=[static])
    assert service.get_scan(plan['scanId'], 'candidates')['items'][0]['evidenceState'] == 'source_supported'
    # Receipt identities must not be reused to rewrite historical observations.
    changed = deepcopy(static); changed['checks']['source']['checked'] = False
    with pytest.raises(Conflict): service.record_validations(plan['scanId'], receipts=[changed])


@pytest.mark.parametrize('safety', ['static', 'active-authorized'])
def test_grant_cannot_run_local_commands_from_agent_tool(tmp_path, safety):
    import sys
    from hermes_security.tools import make_handler
    from hermes_security.validation import mint_grant
    root, service, plan = setup(tmp_path, safety_level=safety)
    sid = plan['scanId']
    service.submit_worker_result(worker(plan, [candidate_for(root)]))
    cid = service.get_scan(sid, 'candidates')['items'][0]['candidateId']
    # Even a stored grant naming local-command (no longer mintable via /security) is refused.
    grant = mint_grant(service.store, sid, origins=['http://127.0.0.1:9'], actions=['local-command'],
                       expires_in_s=600, max_requests=5, created_by='user-command')
    sentinel = tmp_path / 'ran'
    handler = make_handler('security_scan_record_validations', lambda: service)
    out = json.loads(handler({'scan_id': sid, 'plans': [{
        'candidateId': cid, 'kind': 'local-command', 'level': 'active-authorized', 'grantId': grant['grantId'],
        'commands': [[sys.executable, '-c', f"open({str(sentinel)!r},'w');print('MARK')"], [sys.executable, '-c', 'print(1)']],
        'positiveControl': {'commandIndex': 0, 'expectedMarker': 'MARK'}, 'negativeControl': {'commandIndex': 1},
        'cleanup': {'strategy': 'remove-copy'}, 'timeoutS': 2}]}))
    assert out['ok'] is False and out['error']['code'] == 'policy_denied'
    assert not sentinel.exists()
    assert service.store.validations(sid) == []


def test_symlinked_data_dir_ancestor_is_resolved(tmp_path):
    real = tmp_path / 'real'; real.mkdir()
    (tmp_path / 'alias').symlink_to(real)
    root = tmp_path / 'repo'; root.mkdir()
    (root / 'app.py').write_text('x = 1\n')
    service = SecurityService(tmp_path / 'alias' / 'data')
    assert service.data_dir == real / 'data'
    sid = service.start_scan(path=str(root))['scanId']
    assert service.run_detectors(sid, ['builtin-secrets'])['receipts'][0]['status'] == 'ok'


def test_grants_only_apply_to_active_authorized_scans(tmp_path):
    root, service, plan = setup(tmp_path)
    sid = plan['scanId']
    service.submit_worker_result(worker(plan, [candidate_for(root)]))
    cid = service.get_scan(sid, 'candidates')['items'][0]['candidateId']
    grant = service.mint_grant(sid, origins=['http://127.0.0.1:9'], actions=['http-probe'],
                               expires_in_s=600, max_requests=5, created_by='user-command')
    probe = {'candidateId': cid, 'kind': 'http-probe', 'level': 'active-authorized', 'grantId': grant['grantId'],
             'requests': [{'url': 'http://127.0.0.1:9/a'}, {'url': 'http://127.0.0.1:9/b'}],
             'positiveControl': {'requestIndex': 0, 'expectedMarker': 'X'}, 'negativeControl': {'requestIndex': 1},
             'cleanup': {'strategy': 'none'}, 'timeoutS': 1}
    with pytest.raises(PolicyDenied):
        service.record_validations(sid, plans=[probe])
    assert service.store.get_grant(grant['grantId'])['used'] == 0


def test_semantic_subsumption_schema_and_conservation(tmp_path):
    root, service, plan = setup(tmp_path, mode='deep')
    a = candidate_for(root)
    payload = worker(plan, [a], role='deep-pass', attempt='att_one')
    service.submit_worker_result(payload)
    cid = service.get_scan(plan['scanId'], 'candidates')['items'][0]['candidateId']
    b = deepcopy(a); b['identity']['anchor'] = 'app.py/new'; b['provenance']['subsumes'] = [cid]
    service.submit_worker_result(worker(plan, [b], role='deep-pass', attempt='att_two'))
    reduced = service._reduced(plan['scanId'])
    assert not reduced['problems'] and len(reduced['absorbed']) == 1
    assert reduced['retained'][0]['provenance']['supersedes'] == [cid]
    service.finalize(plan['scanId'])


@pytest.mark.parametrize('method,arguments', [
    ('start_scan', {'path': '.', 'mode': []}),
    ('start_scan', {'path': '.', 'safety_level': {}}),
    ('get_scan', {'scan_id': {}}),
    ('list_scans', {'q': {}}),
    ('list_findings', {'severity': {}}),
    ('record_validations', {'scan_id': 'scan_x', 'plans': [{'commands': 5}]}),
    ('triage', {'finding_id': 'x', 'state': []}),
])
def test_public_misuse_is_domain_error(tmp_path, method, arguments):
    service = SecurityService(tmp_path / 'data')
    with pytest.raises(SecurityError): getattr(service, method)(**arguments)


def test_import_sarif_and_untrusted_options(tmp_path):
    root, service, plan = setup(tmp_path)
    sarif = tmp_path / 'results.sarif'
    sarif.write_text(json.dumps({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'test'}}, 'results': [{'ruleId': 'test.rule', 'message': {'text': 'Review code'}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'app.py'}, 'region': {'startLine': 1}}}]}]}]}))
    result = service.import_detector_results(plan['scanId'], sarif_path=str(sarif))
    assert result['inserted'] == 1 and result['receipts'][0]['status'] == 'ok'
    assert service.import_detector_results(plan['scanId'], detector='builtin-secrets', run=True)['receipts']
    with pytest.raises(ValidationError): service.start_scan(path=str(root), detectorOptions={'semgrep': {'work_dir': str(root)}})
