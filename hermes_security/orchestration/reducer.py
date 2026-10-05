"""Conservative root-cause deduplication with auditable source conservation."""
from collections import Counter
from copy import deepcopy


def reduce_candidates(candidates):
    # Candidate identities are plugin-computed. Distinct attempts of one identity
    # are repeated observations, not separate source identities.
    priority = {'runtime_confirmed': 5, 'source_supported': 4, 'rejected': 3, 'inconclusive': 2, 'candidate': 1}
    unique = {}
    for raw in candidates:
        cid = raw['candidateId']
        old = unique.get(cid)
        if old is None or priority.get(raw.get('evidenceState'), 0) > priority.get(old.get('evidenceState'), 0):
            unique[cid] = deepcopy(raw)
        if old:
            unique[cid].setdefault('provenance', {})['workerAttemptIds'] = sorted(set(old.get('provenance', {}).get('workerAttemptIds', []) + raw.get('provenance', {}).get('workerAttemptIds', [])))
    kept, absorbed, rejected = [], [], []
    for cid, row in sorted(unique.items(), key=lambda pair: (-priority.get(pair[1].get('evidenceState'), 0), pair[0])):
        if row.get('evidenceState') == 'rejected':
            rejected.append(row)
            continue
        key = (row['ruleId'], row['identity']['anchor'])
        winner = next((k for k in kept if (k['ruleId'], k['identity']['anchor']) == key), None)
        if winner is None:
            kept.append(row)
        else:
            absorbed.append({'candidateId': cid, 'into': winner['candidateId'], 'reason': 'same ruleId and anchor'})
    # A subsumption statement names every absorbed source; CWE alone is never a key.
    for winner in list(kept):
        if winner not in kept:
            continue
        declared = winner.get('provenance', {}).get('subsumes', [])
        for row in list(kept):
            if row is not winner and row['candidateId'] in declared:
                kept.remove(row)
                for edge in absorbed:
                    if edge['into'] == row['candidateId']:
                        edge['into'] = winner['candidateId']
                absorbed.append({'candidateId': row['candidateId'], 'into': winner['candidateId'], 'reason': 'explicit remediation subsumption'})
    for row in kept:
        ids = sorted(e['candidateId'] for e in absorbed if e['into'] == row['candidateId'])
        provenance = row.setdefault('provenance', {})
        provenance['sourceCandidateIds'] = sorted(set([row['candidateId'], *ids, *provenance.get('sourceCandidateIds', [])]))
        provenance['supersedes'] = ids or None
        provenance['workerAttemptIds'] = sorted({aid for cid in [row['candidateId'], *ids] for aid in unique[cid].get('provenance', {}).get('workerAttemptIds', [])})
        provenance.pop('subsumes', None)
    result = {'retained': kept, 'absorbed': absorbed, 'rejected': rejected}
    result['problems'] = conservation_check(candidates, result)
    return result


def conservation_check(sources, result):
    expected = {c['candidateId'] for c in sources}
    seen = Counter([c['candidateId'] for c in result['retained']] + [c['candidateId'] for c in result['absorbed']] + [c['candidateId'] for c in result['rejected']])
    problems = []
    if set(seen) != expected:
        problems.append('source candidate set changed')
    if any(n != 1 for n in seen.values()):
        problems.append('source candidate accounted for more than once')
    survivors = {c['candidateId'] for c in result['retained']}
    if any(c['into'] not in survivors for c in result['absorbed']):
        problems.append('absorption target is not retained')
    return problems
