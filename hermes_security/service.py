"""The single profile-local orchestrator. No agent input conveys user authority.

Mutations share a scan lease, so finalize cannot race ingestion. The store lease
schema is foreign-keyed to scans; grant:<id> is therefore the owner of a scan
lease rather than a fictitious scan key. This is stricter than a per-grant lock:
all grant consumption for one scan is serialized, including across processes.
All cooperating callers must use this service; direct store calls bypass it.
"""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import json
import os
import shlex
import threading
import uuid

from . import target, detectors, validation, reports, chains
from .canonical import canonical_json, sha256_hex, stable_id, utcnow
from .domain.models import normalize_candidate, promote_to_finding
from .domain.identities import finding_id
from .domain.validate import validate_worker_result, validate_document
from .errors import SecurityError, ValidationError, NotFound, Conflict, SealedError, PolicyDenied
from .store.db import SecurityStore
from .store.artifacts import scan_dir, write_artifact, read_artifact
from .standards import ledger
from .orchestration import METHODOLOGY_VERSION, standard, deep, diff, reducer
from .orchestration.coverage import build_coverage
from .orchestration.worker_protocol import check_candidate


class SecurityService:
    def __init__(self, data_dir: Path, *, profile='default', clock=None):
        # Resolve trusted configuration once (e.g. a symlinked HERMES_HOME); artifact
        # access below this root still refuses symlinks with O_NOFOLLOW.
        self.data_dir = Path(data_dir).resolve()
        if not isinstance(profile, str) or not profile:
            raise ValidationError('profile must be nonempty text')
        self.profile = profile
        self.clock = clock or utcnow
        self.store = SecurityStore(self.data_dir, redactor=target.redact_secrets)
        self._local = threading.local()

    def _now(self):
        value = self.clock()
        return value if isinstance(value, str) else value.strftime('%Y-%m-%dT%H:%M:%SZ')

    def _safe(self, value, *, bounded=True):
        try:
            encoded = self.store._json(value)
        except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
            raise ValidationError('invalid JSON input') from exc
        if bounded and len(encoded.encode()) > 2 * 1024 * 1024:
            raise ValidationError('input exceeds 2 MiB')
        return value

    def _scan(self, scan_id, *, mutable=False, canceled=False):
        if not isinstance(scan_id, str):
            raise ValidationError('scanId must be a string')
        scan = self.store.get_scan(scan_id)
        if mutable:
            if scan['sealed_at']:
                raise SealedError('scan is sealed')
            if scan['status'] == 'canceled' and not canceled:
                raise Conflict('scan is canceled; resume before submitting work')
        return scan

    @contextmanager
    def _mutation(self, scan_id, *, canceled=False, owner=None):
        self._scan(scan_id, mutable=True, canceled=canceled)
        active = getattr(self._local, 'active', {})
        if scan_id in active:
            yield self._scan(scan_id, mutable=True, canceled=canceled)
            return
        self._scan(scan_id, mutable=True, canceled=canceled)
        owner = (owner or 'service') + ':' + uuid.uuid4().hex
        # Plans are bounded to <=200 operations at <=10 seconds each below.
        if not self.store.lease(scan_id, owner, 3600):
            raise Conflict('scan has an active operation; retry later')
        self._local.active = {**active, scan_id: owner}
        stop_renewal = threading.Event()
        def renew():
            while not stop_renewal.wait(60):
                try:
                    if not self.store.lease(scan_id, owner, 3600):
                        return
                except SecurityError:
                    return
        heartbeat = threading.Thread(target=renew, name='security-scan-lease', daemon=True)
        heartbeat.start()
        try:
            yield self._scan(scan_id, mutable=True, canceled=canceled)
        finally:
            stop_renewal.set()
            heartbeat.join(timeout=6)
            self._local.active = active
            if not self.store.is_sealed(scan_id):
                self.store.release(scan_id, owner)

    def _current(self, scan):
        if not target.is_snapshot_current(scan['target'], scan['snapshot_digest']):
            raise Conflict('snapshot changed; start a new scan')

    def _attempts(self, scan_id):
        # The v1 store has no public attempt-list method; keep the read here.
        with self.store._connection() as conn:
            return [dict(r) for r in conn.execute('SELECT * FROM worker_attempts WHERE scan_id=? ORDER BY rowid', (scan_id,))]

    def _packets(self, scan):
        inventory = self.store.inventory(scan['scan_id'])
        profiles = ledger.specialist_profiles_for(scan['options']['surfaces'])
        if scan['mode'] == 'deep':
            return deep.build_packets(scan['scan_id'], inventory, profiles, scan['options']['deep_passes'])
        if scan['mode'] == 'diff':
            packets, _ = diff.build_packets(scan['scan_id'], scan['target'], profiles, manifest=scan['options']['diff'])
            return packets
        return standard.build_packets(scan['scan_id'], inventory, profiles)

    def _plan(self, scan, packets=None):
        refs = Path(__file__).resolve().parents[1] / 'references'
        inventory = self.store.inventory(scan['scan_id'])
        profiles = ledger.specialist_profiles_for(scan['options']['surfaces'])
        excluded = scan['options']['excluded']
        return {'scanId': scan['scan_id'], 'root': scan['root'], 'snapshotDigest': scan['snapshot_digest'],
                'methodologyVersion': METHODOLOGY_VERSION, 'surfaces': scan['options']['surfaces'],
                'specialistProfiles': [{'name': name, 'path': str(refs / 'specialist-profiles' / (name + '.md'))} for name in profiles],
                'lanes': standard.lanes(), 'applicableControls': ledger.applicable_controls(scan['options']['surfaces']),
                'packets': self._packets(scan) if packets is None else packets,
                'workerBriefPath': str(refs / 'worker-packet.md'),
                'submit': {'tool': 'security_scan_submit_worker_result', 'cli': 'PYTHONPATH=' + shlex.quote(str(Path(__file__).resolve().parents[1])) + ' python3 -m hermes_security submit --scan ' + scan['scan_id'] + ' --file <json>'},
                'inventory': {'files': len(inventory), 'bytes': sum(f['size'] for f in inventory), 'lines': sum(f['lines'] for f in inventory), 'truncated': scan['options']['truncated']},
                'excluded': {'total': len(excluded), 'items': excluded}, 'status': scan['status'], 'diff': scan['options'].get('diff')}

    def start_scan(self, **opts):
        self._safe(opts)
        allowed = {'path', 'mode', 'scope', 'base', 'head', 'safety_level', 'allowLocalValidation', 'deep_passes',
                   'budget', 'notes', 'detectors', 'detectorOptions', 'semgrep_config', 'provider', 'model'}
        if set(opts) - allowed:
            raise ValidationError('unknown scan option')
        if not isinstance(opts.get('path'), str):
            raise ValidationError('path is required')
        mode = opts.get('mode', 'standard')
        if not isinstance(mode, str) or mode not in {'standard', 'deep', 'diff'}:
            raise ValidationError('mode must be standard, deep or diff; use record_validations for validation')
        safety = opts.get('safety_level', 'static')
        if not isinstance(safety, str) or safety not in {'static', 'local-safe', 'active-authorized'}:
            raise ValidationError('invalid safety_level')
        if safety == 'local-safe' and opts.get('allowLocalValidation') is not True:
            raise PolicyDenied('local-safe requires explicit user allowLocalValidation')
        if mode != 'diff' and (opts.get('base') is not None or opts.get('head') is not None):
            raise ValidationError('base and head require diff mode')
        for key in ('provider', 'model', 'notes'):
            if opts.get(key) is not None and not isinstance(opts[key], str):
                raise ValidationError('provider, model and notes must be text')
        passes = opts.get('deep_passes', 3)
        if type(passes) is not int or not 1 <= passes <= 8:
            raise ValidationError('deep_passes must be an integer from 1 to 8')
        resolved = target.resolve_target(opts['path'], scope=opts.get('scope'), base=opts.get('base'), head=opts.get('head'), mode=mode)
        root = Path(resolved['root'])
        if self.data_dir == root or root in self.data_dir.parents:
            raise PolicyDenied('plugin data directory must be outside the target tree')
        if mode == 'diff' and resolved['head'] and (resolved['head'] != resolved['revision'] or resolved['dirty']):
            raise Conflict('explicit diff head must be the clean checked-out revision; use a separate worktree')
        inventory = target.build_inventory(resolved)
        resolved.update(snapshotDigest=target.snapshot_digest(inventory, resolved), fileCount=len(inventory['files']))
        options = {**opts, 'surfaces': sorted(ledger.detect_surfaces(inventory['files'])), 'deep_passes': passes,
                   'excluded': inventory['excluded'], 'truncated': inventory['truncated']}
        if mode == 'diff':
            options['diff'] = target.diff_manifest(resolved)
        self._detector_options(options)
        scan = self.store.create_scan(mode=mode, safety_level=safety, target=resolved, inventory=inventory['files'], options=options)
        scan = self.store.set_scan_status(scan['scan_id'], 'awaiting_analysis')
        self.store.add_event(scan['scan_id'], 'scan.started', 'Snapshot inventoried; review packets ready.', {'packetCount': len(self._packets(scan))})
        return self._plan(scan)

    def get_scan(self, scan_id, section=None, limit=50, offset=0):
        scan = self._scan(scan_id)
        self.store._page(limit, offset)
        if section is not None and not isinstance(section, str):
            raise ValidationError('section must be text')
        if section is None:
            return {**scan, 'scanId': scan_id, 'plan': self._plan(scan)}
        if section == 'coverage':
            return self.coverage(scan_id)
        if section == 'activity':
            return self.activity(scan_id, after_id=offset, limit=limit)
        if section == 'chains':
            return self.store.get_chains(scan_id) or self.propose_chains(scan_id)
        if section in {'manifest', 'report'}:
            if not scan['sealed_at']:
                raise Conflict('scan is not finalized')
            raw = read_artifact(scan_dir(self.data_dir, scan_id), 'scan-manifest.json' if section == 'manifest' else 'report.md')
            return json.loads(raw) if section == 'manifest' else {'content': raw.decode()}
        if section == 'inventory':
            rows = self.store.inventory(scan_id)
        elif section in {'findings', 'candidates'}:
            if section == 'findings' and scan['sealed_at']:
                return self.store.list_findings(scan_id=scan_id, limit=limit, offset=offset)
            rows = self._candidates(scan_id)
        elif section == 'workers':
            rows = self._attempts(scan_id)
        elif section == 'detectors':
            rows = self.store.detector_runs(scan_id)
        elif section == 'validations':
            rows = self.store.validations(scan_id)
        else:
            raise ValidationError('unknown scan section')
        return {'items': rows[offset:offset + limit], 'total': len(rows)}

    def _coverage_input(self, scan, units, source):
        if not isinstance(units, list) or len(units) > 50000:
            raise ValidationError('coverage must be a bounded list')
        paths = self.store.inventory_paths(scan['scan_id'])
        for key in ('changed', 'added', 'deleted'):
            paths.update(scan['options'].get('diff', {}).get(key, []))
        lanes = {r['id'] for r in standard.lanes()}
        controls = {r['id'] for r in ledger.load_asvs()['controls']}
        result = []
        for unit in units:
            if not isinstance(unit, dict):
                raise ValidationError('coverage unit must be an object')
            ident = unit.get('unit', unit.get('unitId'))
            if not isinstance(ident, str) or ':' not in ident:
                raise ValidationError('invalid coverage unit identifier')
            kind, value = ident.split(':', 1)
            valid = (kind == 'file' and value in paths) or (kind == 'lane' and value in lanes) or (kind == 'asvs' and value in controls)
            if not valid or unit.get('state') not in {'reviewed', 'not_applicable', 'deferred', 'unsupported', 'unknown', 'failed'}:
                raise ValidationError('unknown review unit or coverage state')
            note = unit.get('note', unit.get('reason', 'explicit review disposition'))
            if not isinstance(note, str):
                raise ValidationError('coverage note must be text')
            result.append({'unitId': ident, 'kind': kind, 'state': unit['state'], 'reason': note, 'evidence': [source]})
        self._safe(result)
        return result

    def checkpoint(self, scan_id, coverage=None, note=None):
        with self._mutation(scan_id) as scan:
            if note is not None and not isinstance(note, str):
                raise ValidationError('checkpoint note must be text')
            self._safe(note)
            source = stable_id('checkpoint', scan_id, coverage, note)
            units = self._coverage_input(scan, coverage or [], source)
            self.store.record_coverage(scan_id, units, source=source)
            self.store.add_event(scan_id, 'scan.checkpoint', note or 'Coverage checkpoint recorded.')
            return {'scanId': scan_id, 'recorded': len(units), 'coverage': self.coverage(scan_id)}

    def submit_worker_result(self, payload):
        problems = validate_worker_result(payload)
        if problems:
            # Schema paths can contain attacker-supplied field names, so do not echo them.
            raise ValidationError('worker result violates the input contract')
        scan_id = payload['scanId']
        with self._mutation(scan_id) as scan:
            if payload['snapshotDigest'] != scan['snapshot_digest']:
                raise Conflict('worker snapshotDigest does not match scan')
            self._current(scan)
            packets = {p['packetId']: p for p in self._packets(scan)}
            packet = payload['packetId']
            if packet is not None and (packet not in packets or packets[packet]['role'] != payload['workerRole']):
                raise ValidationError('packet does not belong to this scan or role')
            aid = payload['attemptId']
            units = self._coverage_input(scan, payload['coverage'], aid)
            self._safe({'notes': payload['notes'], 'negativeResults': payload['negativeResults']})
            inventory = self.store.inventory(scan_id)
            accepted, rejected = [], []
            for index, raw in enumerate(payload['candidates']):
                try:
                    candidate = check_candidate(raw, scan=scan, inventory=inventory, attempt_id=aid)
                    candidate['diffAttribution'] = diff.attribution(candidate, scan['options']['diff']) if scan['mode'] == 'diff' else None
                    self._safe(candidate)
                    accepted.append(candidate)
                except SecurityError as exc:
                    rejected.append({'index': index, 'reason': str(exc)})
            # Detect changes during excerpt reads before committing any evidence.
            self._current(scan)
            digest = sha256_hex(canonical_json(payload))
            attempt = self.store.record_attempt(scan_id, aid, payload['workerRole'], packet_id=packet)
            if attempt['status'] != 'running':
                if attempt['status'] == 'accepted' and attempt['result_digest'] == digest:
                    return {'scanId': scan_id, 'attemptId': aid, 'inserted': 0, 'duplicates': len(accepted), 'rejected': rejected}
                raise Conflict('attempt already finished with a different result')
            counts = self.store.upsert_candidates(scan_id, aid, accepted)
            if payload['workerRole'] == 'validator':
                for candidate in accepted:
                    state = candidate['evidenceState']
                    if state in {'source_supported', 'rejected', 'inconclusive'}:
                        self.store.set_candidate_state(scan_id, candidate['candidateId'], state, reason='Validator source review; runtime NOT RUN.')
            self.store.record_coverage(scan_id, units, source=aid)
            self.store.finish_attempt(scan_id, aid, 'accepted', result_digest=digest)
            self.store.add_event(scan_id, 'worker.accepted', 'Worker result recorded.', {'attemptId': aid, **counts, 'rejected': rejected, 'negativeResults': payload['negativeResults'], 'notes': payload['notes']})
            return {'scanId': scan_id, 'attemptId': aid, **counts, 'rejected': rejected}

    def _detector_options(self, options):
        config = deepcopy(options.get('detectorOptions', {}))
        if not isinstance(config, dict) or set(config) - {'semgrep'}:
            raise ValidationError('only explicit semgrep detector configuration is supported')
        if 'semgrep_config' in options:
            config['semgrep'] = {'config': options['semgrep_config']}
        if 'semgrep' in config:
            if not isinstance(config['semgrep'], dict) or set(config['semgrep']) - {'config'} or not isinstance(config['semgrep'].get('config'), str):
                raise ValidationError('semgrep requires an explicit rules config path')
            rules = Path(config['semgrep']['config']).expanduser()
            if not rules.is_file() or rules.is_symlink():
                raise ValidationError('semgrep config must be an existing local rules file, not a registry or URL')
            config['semgrep']['config'] = str(rules.resolve())
        return config

    def _ingest_detectors(self, scan, candidates, receipts):
        scan_id = scan['scan_id']
        aid = stable_id('att', scan_id, 'detectors', receipts)
        old = self.store.record_attempt(scan_id, aid, 'detector')
        if old['status'] == 'accepted':
            return {'scanId': scan_id, 'inserted': 0, 'duplicates': len(candidates), 'receipts': receipts}
        normalized = []
        for candidate in candidates:
            row = normalize_candidate(candidate, scan_id=scan_id)
            row['source'] = 'detector'
            row['evidenceState'] = 'candidate'
            if scan['mode'] == 'diff':
                row['diffAttribution'] = diff.attribution(row, scan['options']['diff'])
            self._safe(row)
            normalized.append(row)
        result = self.store.upsert_candidates(scan_id, aid, normalized)
        for receipt in receipts:
            self.store.record_detector_run(scan_id, receipt)
            state = {'ok': 'reviewed', 'unavailable': 'unsupported'}.get(receipt['status'], 'failed')
            self.store.record_coverage(scan_id, [{'unitId': 'detector:' + receipt['detector'], 'state': state, 'reason': receipt.get('error') or receipt['status'], 'evidence': [receipt['receiptId']]}], source=receipt['receiptId'])
        self.store.finish_attempt(scan_id, aid, 'accepted', result_digest=sha256_hex(canonical_json(receipts)))
        self.store.add_event(scan_id, 'detectors.recorded', 'Detector receipts recorded.', {'receiptIds': [r['receiptId'] for r in receipts]})
        return {'scanId': scan_id, **result, 'receipts': receipts}

    def _work(self, scan_id):
        path = scan_dir(self.data_dir, scan_id) / 'work'
        if path.is_symlink():
            raise ValidationError('work directory cannot be a symlink')
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
        return path

    def run_detectors(self, scan_id, names=None):
        with self._mutation(scan_id) as scan:
            self._current(scan)
            names = names if names is not None else scan['options'].get('detectors', ['builtin-secrets'])
            if not isinstance(names, list) or len(names) > 20 or any(not isinstance(n, str) for n in names):
                raise ValidationError('detector names must be a bounded string list')
            self._safe(names)
            resolved = {**scan['target'], 'detectorOptions': self._detector_options(scan['options'])}
            candidates, receipts = detectors.run_detectors(list(dict.fromkeys(names)), resolved, {'files': self.store.inventory(scan_id)}, self._work(scan_id))
            self._current(scan)
            return self._ingest_detectors(scan, candidates, receipts)

    def import_detector_results(self, scan_id, detector=None, sarif_path=None, run=False):
        if run:
            if sarif_path is not None:
                raise ValidationError('choose detector execution or SARIF import')
            return self.run_detectors(scan_id, [detector] if detector else None)
        if not isinstance(sarif_path, (str, Path)):
            raise ValidationError('sarif_path is required')
        with self._mutation(scan_id) as scan:
            self._current(scan)
            candidates, receipt = detectors.import_sarif(sarif_path, target=scan['target'], inventory={'files': self.store.inventory(scan_id)}, detector_name=detector or 'sarif')
            return self._ingest_detectors(scan, candidates, [receipt])

    def _candidates(self, scan_id):
        rows = self.store.list_candidates(scan_id)
        receipts = self.store.validations(scan_id)
        by_candidate = {}
        for receipt in receipts:
            by_candidate.setdefault(receipt['candidateId'], []).append(receipt)
        for row in rows:
            reason = row.pop('dispositionReason', None)
            if reason and row['evidenceState'] in {'rejected', 'inconclusive'}:
                row.setdefault('proofGaps', []).append(reason)
            rs = by_candidate.get(row['candidateId'], [])
            if rs:
                last = rs[-1]
                row['validation'] = {'status': last['status'], 'level': last['level'], 'receiptIds': [r['receiptId'] for r in rs], 'summary': '; '.join(last.get('notes', []))}
        return rows

    def record_validations(self, scan_id, receipts=None, plans=None, *, user_authorized=False):
        if receipts is not None and plans is not None:
            raise ValidationError('choose receipts or plans')
        inputs = plans if plans is not None else receipts
        if not isinstance(inputs, list) or len(inputs) > 200 or any(not isinstance(x, dict) for x in inputs):
            raise ValidationError('validation inputs must be a bounded object list')
        self._safe(inputs)
        for item in inputs:
            if not isinstance(item.get('candidateId'), str) or not isinstance(item.get('level', 'static'), str):
                raise ValidationError('validation requires candidateId and a string level')
            if plans is not None and any(not isinstance(item.get(k, []), list) for k in ('requests', 'commands')):
                raise ValidationError('plan operations must be lists')
            if item.get('grantId') is not None and not isinstance(item['grantId'], str):
                raise ValidationError('grantId must be a string')
        if plans is not None and sum(len(p.get('requests', [])) + len(p.get('commands', [])) for p in inputs) > 200:
            raise PolicyDenied('runtime operation budget exceeded')
        grant_ids = {p.get('grantId') for p in inputs if p.get('grantId')}
        owner = ('grant:' + next(iter(grant_ids))) if len(grant_ids) == 1 else None
        with self._mutation(scan_id, owner=owner) as scan:
            self._current(scan)
            candidates = {c['candidateId']: c for c in self._candidates(scan_id)}
            recorded = []
            for item in inputs:
                cid = item.get('candidateId')
                if cid not in candidates:
                    raise NotFound('candidate not found in scan')
                candidate = candidates[cid]
                level = item.get('level', 'static')
                if plans is None:
                    problems = validate_document('validation-receipt', item)
                    if problems:
                        raise ValidationError('invalid validation receipt')
                    validation.validate_receipt(item)
                    if level != 'static':
                        # Execution observations must be generated here, not claimed by an agent.
                        known = self.store.validations(scan_id, cid)
                        if item not in known:
                            raise PolicyDenied('runtime receipts must come from service-executed plans')
                    receipt = item
                else:
                    plan = {**item, 'scanId': scan_id}
                    grant = None
                    if level == 'local-safe' and (scan['safety_level'] != 'local-safe' or user_authorized is not True):
                        raise PolicyDenied('local-safe execution requires scan opt-in and a direct user-authorized call')
                    # Local commands are CLI-only; a grant must not let agent tool calls run them.
                    if item.get('kind') == 'local-command' and level != 'local-safe':
                        raise PolicyDenied('local commands require a local-safe scan and the CLI --allow-local flag')
                    if level == 'active-authorized':
                        if scan['safety_level'] != 'active-authorized':
                            raise PolicyDenied('active-authorized execution requires an active-authorized scan')
                        if not isinstance(item.get('grantId'), str):
                            raise PolicyDenied('active-authorized execution requires a grant')
                        try:
                            grant = self.store.get_grant(item['grantId'])
                        except NotFound as exc:
                            raise PolicyDenied('active-authorized execution requires a valid grant') from exc
                    safety = 'static' if level == 'static' else ('active-authorized' if grant else scan['safety_level'])
                    validation.check_plan(plan, grant=grant, safety_level=safety, now=self._now())
                    if level == 'static':
                        receipt = validation.static_receipt(candidate, checks=plan.get('checks', {}))
                    else:
                        # Enforce a bounded lease horizon; the runner has per-operation timeouts.
                        if type(plan.get('timeoutS', 10)) not in (int, float) or not 0 < plan.get('timeoutS', 10) <= 10:
                            raise PolicyDenied('runtime timeoutS must be at most 10 seconds per operation')
                        if len(plan.get('requests', [])) + len(plan.get('commands', [])) > 200:
                            raise PolicyDenied('runtime operation budget exceeded')
                        if plan['kind'] == 'http-probe':
                            receipt = validation.run_http(plan, grant=grant, store=self.store)
                        else:
                            receipt = validation.run_local(plan, target=scan['target'], workdir_parent=self._work(scan_id), grant=grant)
                self._safe(receipt)
                existing = next((r for r in self.store.validations(scan_id) if r['receiptId'] == receipt['receiptId']), None)
                if existing is not None and existing != receipt:
                    raise Conflict('receipt identity already records a different observation')
                state = validation.next_evidence_state(candidate['evidenceState'], receipt)
                self.store.record_validation(scan_id, receipt)
                self.store.set_candidate_state(scan_id, cid, state, reason='Validation receipt recorded: ' + receipt['receiptId'])
                candidate['evidenceState'] = state
                recorded.append(receipt)
            self.store.add_event(scan_id, 'validations.recorded', 'Validation receipts recorded.', {'count': len(recorded)})
            return {'scanId': scan_id, 'receipts': recorded}

    def _reduced(self, scan_id):
        result = reducer.reduce_candidates(self._candidates(scan_id))
        if result['problems']:
            raise Conflict('candidate conservation check failed')
        return result

    def _chain_inputs(self, scan, candidates):
        result = []
        for row in candidates:
            if row['evidenceState'] not in {'candidate', 'source_supported', 'runtime_confirmed'}:
                continue
            item = deepcopy(row)
            item.update(findingId=finding_id(scan['repo_key'], item['ruleId'], item['identity']['anchor']), scanId=scan['scan_id'], snapshotDigest=scan['snapshot_digest'])
            result.append(item)
        return result

    def propose_chains(self, scan_id):
        scan = self._scan(scan_id)
        return chains.build_chains_doc(scan_id, self._chain_inputs(scan, self._reduced(scan_id)['retained']), snapshot_digest=scan['snapshot_digest'])

    def record_chains(self, scan_id, explanations=None):
        self._safe(explanations)
        if explanations is not None and not isinstance(explanations, dict):
            raise ValidationError('chain explanations must be an object')
        with self._mutation(scan_id) as scan:
            doc = chains.build_chains_doc(scan_id, self._chain_inputs(scan, self._reduced(scan_id)['retained']), snapshot_digest=scan['snapshot_digest'], explanations=explanations)
            return self.store.record_chains(scan_id, doc)

    def coverage(self, scan_id):
        scan = self._scan(scan_id)
        if scan['sealed_at']:
            return json.loads(read_artifact(scan_dir(self.data_dir, scan_id), 'coverage.json'))
        return build_coverage(scan, self.store.inventory(scan_id), self.store.coverage_units(scan_id), self._attempts(scan_id), self.store.detector_runs(scan_id), self._packets(scan), self._candidates(scan_id))

    def finalize(self, scan_id):
        with self._mutation(scan_id) as scan:
            reduced = self._reduced(scan_id)
            findings, retained, gaps = [], [], []
            for row in reduced['retained'] + reduced['rejected']:
                if row['evidenceState'] in {'source_supported', 'runtime_confirmed'}:
                    try:
                        problems = reports.validate_finding_sections(row)
                        if problems:
                            raise ValidationError('; '.join(problems))
                        findings.append(promote_to_finding(row, scan_id=scan_id, repo_key=scan['repo_key']))
                        continue
                    except ValidationError as exc:
                        row = deepcopy(row)
                        row['evidenceState'] = 'inconclusive'
                        row.setdefault('proofGaps', []).append(str(exc))
                        gaps.append('Candidate ' + row['candidateId'] + ' has incomplete report sections.')
                row.setdefault('proofGaps', []).append('Not promoted to a reportable finding.')
                row.get('provenance', {}).pop('subsumes', None)
                retained.append(row)
            coverage = self.coverage(scan_id)
            if not target.is_snapshot_current(scan['target'], scan['snapshot_digest']):
                gaps.append('Target changed after this recorded snapshot; evidence describes the original snapshot only.')
            if gaps:
                coverage['gaps'].extend(gaps)
                coverage['completeness'] = 'partial'
            # Rebuild eligibility after final report validation; never seal dangling chain references.
            saved = self.store.get_chains(scan_id)
            explanations = {c['chainId']: {'title': c['title'], 'summary': c['summary']} for c in (saved or {}).get('chains', [])}
            chain_inputs = [{**f, 'scanId': scan_id, 'snapshotDigest': scan['snapshot_digest']} for f in findings]
            chains_doc = chains.build_chains_doc(scan_id, chain_inputs, snapshot_digest=scan['snapshot_digest'], explanations=explanations)
            manifest = {'documentType': 'hermes-security.scan-manifest', 'schemaVersion': '1.0', 'scanId': scan_id,
                        'producer': {'name': 'hermes-security', 'version': '0.1.0'}, 'methodologyVersion': METHODOLOGY_VERSION,
                        'mode': scan['mode'], 'safetyLevel': scan['safety_level'], 'status': 'completed' if coverage['completeness'] == 'complete' else 'partial',
                        'target': scan['target'], 'runtime': {'provider': scan['options'].get('provider'), 'model': scan['options'].get('model'), 'profile': self.profile, 'fallbacks': []},
                        'startedAt': scan['created_at'], 'finishedAt': self._now(), 'counts': {}, 'artifacts': {}, 'supersedes': None}
            findings_doc = {'documentType': 'hermes-security.findings', 'schemaVersion': '1.0', 'scanId': scan_id, 'findings': findings, 'retained': retained}
            bundle = reports.finalize_bundle(manifest=manifest, findings_doc=findings_doc, coverage=coverage, chains_doc=chains_doc)
            directory = scan_dir(self.data_dir, scan_id)
            for rel, data in bundle.items():
                self._safe(json.loads(data) if rel.endswith(('.json', '.sarif')) else data.decode(), bounded=False)
                write_artifact(directory, rel, data)
            verified = reports.verify_bundle(directory)
            if not verified['ok']:
                raise Conflict('artifact verification failed')
            manifest = json.loads(bundle['scan-manifest.json'])
            self.store.record_chains(scan_id, chains_doc)
            # Store v1 rejects index writes after sealing; index and status must precede seal.
            self.store.upsert_finding_index(scan_id, findings)
            self.store.set_scan_status(scan_id, manifest['status'])
            self.store.seal(scan_id, manifest['seal']['digest'], str(directory))
            self.store.add_event(scan_id, 'scan.finalized', 'Verified bundle sealed.', {'status': manifest['status']})
            return {'scanId': scan_id, 'status': manifest['status'], 'manifest': manifest, 'artifactDir': str(directory), 'verified': verified}

    def cancel(self, scan_id):
        with self._mutation(scan_id, canceled=True):
            for attempt in self._attempts(scan_id):
                if attempt['status'] == 'running':
                    self.store.finish_attempt(scan_id, attempt['attempt_id'], 'canceled')
            self.store.set_scan_status(scan_id, 'canceled')
            self.store.add_event(scan_id, 'scan.canceled', 'Scan canceled; outstanding work is not accepted.')
            return {'scanId': scan_id, 'status': 'canceled'}

    def resume(self, scan_id):
        with self._mutation(scan_id, canceled=True) as scan:
            self._current(scan)
            attempts = self._attempts(scan_id)
            accepted = {a['packet_id'] for a in attempts if a['status'] == 'accepted'}
            packets = [p for p in self._packets(scan) if p['packetId'] not in accepted]
            for attempt in attempts:
                if attempt['status'] == 'running':
                    self.store.finish_attempt(scan_id, attempt['attempt_id'], 'missing', error='Interrupted before an accepted result.')
            for packet in packets:
                prior = [a for a in attempts if a['packet_id'] == packet['packetId']]
                if prior:
                    packet['attemptId'] = stable_id('att', scan_id, packet['packetId'], 'resume', len(prior))
            stop = None
            if scan['mode'] == 'deep':
                known, counts = set(), []
                candidates = self._candidates(scan_id)
                for packet in self._packets(scan):
                    matched = [a for a in attempts if a['packet_id'] == packet['packetId'] and a['status'] == 'accepted']
                    if not matched:
                        break
                    aids = {a['attempt_id'] for a in matched}
                    roots = {(c['ruleId'], c['identity']['anchor']) for c in candidates if aids.intersection(c.get('provenance', {}).get('workerAttemptIds', []))}
                    counts.append(len(roots - known)); known.update(roots)
                stop = deep.stop_reason(counts, scan['options']['deep_passes'])
                if stop:
                    packets = []
            self.store.set_scan_status(scan_id, 'awaiting_analysis')
            self.store.add_event(scan_id, 'scan.resumed', 'Remaining review packets returned.', {'packetCount': len(packets), 'stopReason': stop})
            return {**self._plan(scan, packets), 'status': 'awaiting_analysis', 'stopReason': stop}

    def export(self, scan_id, fmt):
        scan = self._scan(scan_id)
        if not scan['sealed_at']:
            raise Conflict('scan must be finalized before export')
        if not isinstance(fmt, str) or fmt not in {'md', 'sarif', 'json', 'csv'}:
            raise ValidationError('unsupported export format')
        data, content_type, filename = reports.export(scan_dir(self.data_dir, scan_id), fmt)
        return {'scanId': scan_id, 'content': data.decode('utf-8'), 'contentType': content_type, 'filename': filename}

    def summary(self):
        with self.store._connection() as conn:
            statuses = {r[0]: r[1] for r in conn.execute('SELECT status,count(*) FROM scans GROUP BY status')}
            count = conn.execute('SELECT count(DISTINCT finding_id) FROM findings').fetchone()[0]
            repositories = conn.execute('SELECT count(*) FROM repositories').fetchone()[0]
        return {'scans': sum(statuses.values()), 'statuses': statuses, 'findings': count, 'repositories': repositories, 'profile': self.profile}

    def _filters(self, filters, allowed):
        if set(filters) - set(allowed):
            raise ValidationError('unknown list filter')
        for key, value in filters.items():
            if value is None:
                continue
            if key in {'limit', 'offset'}:
                if type(value) is not int or value < 0 or (key == 'limit' and value > 1000):
                    raise ValidationError('pagination requires nonnegative integers; limit <=1000')
            elif key == 'chained':
                if type(value) is not bool:
                    raise ValidationError('chained must be a boolean')
            elif not isinstance(value, str):
                raise ValidationError('filter must be text')
        self._safe(filters)

    def list_scans(self, **filters):
        self._filters(filters, {'q', 'status', 'repo_key', 'limit', 'offset'})
        return self.store.list_scans(**filters)

    def workbench_scans(self, *, q=None, status=None, mode=None, limit=50, offset=0):
        """Read-only SQL pagination including the desktop's scan-mode filter."""
        self._filters(dict(q=q, status=status, mode=mode, limit=limit, offset=offset),
                      {'q', 'status', 'mode', 'limit', 'offset'})
        terms, args = [], []
        for key, value in [('status', status), ('mode', mode)]:
            if value is not None:
                terms.append(key + '=?'); args.append(value)
        if q:
            terms.append('(root LIKE ? OR scan_id LIKE ?)'); args.extend(['%' + q + '%'] * 2)
        where = ' WHERE ' + ' AND '.join(terms) if terms else ''
        with self.store._connection() as conn:
            total = conn.execute('SELECT count(*) FROM scans' + where, args).fetchone()[0]
            ids = conn.execute('SELECT scan_id FROM scans' + where + ' ORDER BY rowid DESC LIMIT ? OFFSET ?', args + [limit, offset])
            items = [self.store._scan(conn, row[0]) for row in ids]
            for item in items:
                # Findings are indexed at seal time; unsealed scans have no counts yet.
                item['counts'] = None if not item['sealed_at'] else {
                    sev: n for sev, n in conn.execute(
                        'SELECT severity,count(DISTINCT finding_id) FROM findings WHERE scan_id=? GROUP BY severity',
                        (item['scan_id'],))}
        return {'items': items, 'total': total}

    def workbench_findings(self, *, q=None, triage=None, severity=None, evidence_state=None,
                           validation_level=None, repo_key=None, owasp=None, source=None,
                           chained=None, limit=50, offset=0):
        """Filter all workbench fields before LIMIT; never select evidence blobs.

        The v1 store lacks validation-level/source filters. Keep this additive
        query here rather than exposing database access to HTTP handlers.
        Source accepts worker/detector provenance or an exact detector name.
        """
        filters = dict(q=q, triage=triage, severity=severity, evidence_state=evidence_state,
                       validation_level=validation_level, repo_key=repo_key, owasp=owasp,
                       source=source, chained=chained, limit=limit, offset=offset)
        self._filters(filters, filters.keys())
        terms, args = [], []
        for key, value in [('severity', severity), ('evidence_state', evidence_state), ('repo_key', repo_key),
                           ('chained', None if chained is None else int(chained))]:
            if value is not None:
                terms.append('f.' + key + '=?'); args.append(value)
        if triage is not None:
            terms.append("COALESCE(t.state,'open')=?"); args.append(triage)
        if validation_level is not None:
            terms.append("json_extract(f.data,'$.validation.level')=?"); args.append(validation_level)
        if owasp is not None:
            terms.append('EXISTS(SELECT 1 FROM json_each(f.owasp) WHERE value=?)'); args.append(owasp)
        if source is not None:
            terms.append("(json_extract(f.data,'$.source')=? OR EXISTS(SELECT 1 FROM json_each(f.detectors) WHERE value=?) "
                         "OR (?='detector' AND json_array_length(f.detectors)>0) "
                         "OR (?='worker' AND json_array_length(json_extract(f.data,'$.provenance.workerAttemptIds'))>0))")
            args.extend([source] * 4)
        if q:
            columns = ['title', 'path', 'category', 'cwe', 'chain_text', 'root', 'repo_key']
            terms.append('(' + ' OR '.join('f.' + key + ' LIKE ?' for key in columns) + ')')
            args.extend(['%' + q + '%'] * len(columns))
        base = ' FROM findings f LEFT JOIN triage t ON t.finding_id=f.finding_id'
        if terms:
            base += ' WHERE ' + ' AND '.join(terms)
        columns = ('f.finding_id,f.occurrence_id,f.scan_id,f.severity,f.evidence_state,f.title,f.repo_key,f.root,'
                   'f.path,f.category,f.cwe,f.owasp,f.detectors,f.chained,f.sealed_at,'
                   "json_extract(f.data,'$.validation.level') AS validation_level,"
                   "COALESCE(t.state,'open') AS triage_state,t.note AS triage_note,t.updated_at AS triage_updated_at")
        with self.store._connection() as conn:
            total = conn.execute('SELECT count(*)' + base, args).fetchone()[0]
            items = []
            for row in conn.execute('SELECT ' + columns + base + ' ORDER BY f.rowid DESC LIMIT ? OFFSET ?', args + [limit, offset]):
                item = dict(row)
                for key in ('cwe', 'owasp', 'detectors'):
                    item[key] = json.loads(item[key])
                item['chained'] = bool(item['chained'])
                item['triage'] = {'state': item.pop('triage_state'), 'note': item.pop('triage_note'),
                                  'updated_at': item.pop('triage_updated_at')}
                items.append(item)
        return {'items': items, 'total': total}

    def activity(self, scan_id, after_id=0, limit=200):
        self._scan(scan_id)
        return {'items': self.store.events(scan_id, after_id=after_id, limit=limit)}

    def list_findings(self, **filters):
        self._filters(filters, {'q', 'severity', 'evidence_state', 'triage', 'repo_key', 'owasp', 'detector', 'chained', 'scan_id', 'limit', 'offset'})
        return self.store.list_findings(**filters)

    def get_finding(self, finding_id):
        if not isinstance(finding_id, str):
            raise ValidationError('findingId must be text')
        return self.store.get_finding(finding_id)

    def triage(self, finding_id, state, note=None):
        if not isinstance(finding_id, str) or not isinstance(state, str) or (note is not None and not isinstance(note, str)):
            raise ValidationError('triage identifier, state and note must be text')
        self._safe(note)
        return self.store.set_triage(finding_id, state, note=note)

    def patch_preview(self, finding_id):
        row = self.get_finding(finding_id)
        finding = row.get('data', row)
        if isinstance(finding, str):
            finding = json.loads(finding)
        remediation = finding.get('remediation', {})
        lines = ['Read-only remediation proposal (no files changed)', '', remediation.get('summary', ''), '', 'Regression tests:']
        lines += ['- ' + t for t in remediation.get('regressionTests', [])]
        for e in finding.get('codeEvidence', []):
            lines += ['', f"{e['path']}:{e['startLine']}-{e['endLine']}", e['code']]
        return {'findingId': finding_id, 'readOnly': True, 'content': '\n'.join(lines)}

    def list_repositories(self, **filters):
        self._filters(filters, {'limit', 'offset'})
        return self.store.list_repositories(**filters)

    def mint_grant(self, scan_id, **opts):
        """USER-ONLY: direct slash command/CLI; never register this as an agent tool."""
        with self._mutation(scan_id):
            return validation.mint_grant(self.store, scan_id, **opts)

    def revoke_grant(self, grant_id):
        """USER-ONLY: direct slash command/CLI; never register this as an agent tool."""
        if not isinstance(grant_id, str):
            raise ValidationError('grantId must be text')
        grant = self.store.get_grant(grant_id)
        with self._mutation(grant['scanId'], canceled=True, owner='grant:' + grant_id):
            return self.store.revoke_grant(grant_id)
