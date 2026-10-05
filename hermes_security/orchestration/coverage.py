"""Coverage closure is independent of the number of findings."""
from ..standards import ledger


def build_coverage(scan, inventory, units, attempts, detector_runs, packets, findings):
    by_id = {}
    for unit in units:
        ident = unit.get('unitId', unit.get('unit'))
        by_id[ident] = {'unitId': ident, 'kind': ident.split(':', 1)[0], 'state': unit['state'],
                        'reason': unit.get('reason', unit.get('note', 'explicit review disposition')),
                        'evidence': unit.get('evidence', [])}
    review_paths = {f['path'] for f in inventory}
    diff = scan['options'].get('diff', {})
    review_paths.update(diff.get('deleted', []))
    review_paths.update(diff.get('changed', []))
    review_paths.update(diff.get('added', []))
    for path in sorted(review_paths):
        ident = 'file:' + path
        by_id.setdefault(ident, {'unitId': ident, 'kind': 'file', 'state': 'unknown', 'reason': 'file has no accepted review', 'evidence': []})
    standards = ledger.build_ledger(scan['options']['surfaces'], list(by_id.values()), findings)
    gaps = ledger.mandatory_gaps(standards)
    done = {'reviewed', 'not_applicable'}
    files = [by_id['file:' + p] for p in sorted(review_paths)]
    for unit in by_id.values():
        if unit['state'] not in done:
            gaps.append(unit['unitId'] + ' is ' + unit['state'] + ': ' + unit['reason'])
    workers = [{'attemptId': a['attempt_id'], 'role': a['role'], 'status': a['status'] if a['status'] in {'accepted', 'rejected', 'late'} else 'missing'} for a in attempts]
    accepted = {a['packet_id'] for a in attempts if a['status'] == 'accepted'}
    for packet in packets:
        if packet['packetId'] not in accepted:
            workers.append({'attemptId': packet.get('attemptId', 'att_missing_' + packet['packetId'][4:]), 'role': packet['role'], 'status': 'missing'})
            gaps.append('Worker packet ' + packet['packetId'] + ' has no accepted result.')
    if scan['options'].get('truncated'):
        gaps.append('Inventory was truncated.')
    for excluded in scan['options'].get('excluded', []):
        # Scope/policy exclusions are intentional; unreadable or unsafe files are not.
        if excluded['reason'] not in {'out_of_scope', 'git_metadata', 'vendored'}:
            gaps.append('Excluded ' + excluded['path'] + ': ' + excluded['reason'])
    for run in detector_runs:
        if run['status'] != 'ok' or run.get('truncated') or run.get('error'):
            gaps.append('Detector ' + run['detector'] + ' did not complete: ' +
                        (run.get('error') or ('output truncated' if run.get('truncated') else run['status'])))
    return {'documentType': 'hermes-security.coverage', 'schemaVersion': '1.0', 'scanId': scan['scan_id'],
            'completeness': 'partial' if gaps else 'complete',
            'files': {'total': len(files), 'reviewed': sum(f['state'] in done for f in files),
                      'deferred': sum(f['state'] == 'deferred' for f in files), 'unsupported': sum(f['state'] == 'unsupported' for f in files),
                      'excluded': scan['options'].get('excluded', [])},
            'units': list(by_id.values()), 'standards': standards, 'detectors': detector_runs, 'workers': workers, 'gaps': list(dict.fromkeys(gaps))}
