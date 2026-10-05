# Adapted from openai/codex-security@89aae24 plugins/codex-security/scripts/report_projection.py (Apache-2.0). Modified for hermes-security.
"""Deterministic layered Markdown; quoted code remains byte-for-byte unchanged."""
from __future__ import annotations

import re
from collections import Counter
from .copy import SEVERITIES, _reportable, human_label


def _text(value, fallback='Not recorded'):
    """Escape untrusted prose so it cannot create headings, links, or HTML."""
    text = ' '.join(str(value).split()) if value is not None else ''
    text = text or fallback
    return re.sub(r'([\\`*\[\]<>_#|])', r'\\\1', text)


def _bullets(values, fallback='None recorded.'):
    return '\n'.join('- ' + _text(v) for v in values) if values else fallback


def render_markdown(manifest: dict, findings_doc: dict, coverage: dict, chains_doc: dict) -> str:
    """Project semantic documents without reading the target or generating times."""
    findings = _reportable(findings_doc)
    target = manifest.get('target', {})
    revision = target.get('revision') or target.get('snapshotDigest') or 'Snapshot not recorded'
    parts = [f"# Security review: {_text(target.get('root'))} — {_text(revision)}",
             f"This review identified {len(findings)} reportable finding{'s' if len(findings) != 1 else ''}. "
             'The sections below explain the affected behavior, supporting evidence, uncertainty, and recommended changes.']
    incomplete = coverage.get('completeness') != 'complete' or manifest.get('status') in {'partial', 'canceled', 'failed', 'interrupted'}
    if incomplete:
        gaps = coverage.get('gaps', [])
        if not gaps:
            gaps = [f"The scan ended with status {manifest.get('status', 'unknown')}; not all requested review work was established as complete."]
        # Keep the banner short; the full gap list is rendered under Limitations.
        summary = _text(gaps[0]) if len(gaps) == 1 else f'{len(gaps)} coverage gaps are listed under Limitations.'
        parts.append('> **This scan is incomplete.** ' + summary +
                     ' Absence of findings does not establish that the target is safe.')
    totals = Counter(f['severity']['level'] for f in findings)
    parts.extend(['## Severity totals', '| Severity | Findings |\n|---|---:|\n' + '\n'.join(f'| {human_label(s)} | {totals[s]} |' for s in SEVERITIES),
                  '## Coverage', f"Review coverage: {human_label(coverage.get('completeness', 'unknown'))}."])
    files = coverage.get('files', {})
    parts.append(f"Files: {files.get('reviewed', 0)} reviewed of {files.get('total', 0)}; "
                 f"{files.get('deferred', 0)} deferred; {files.get('unsupported', 0)} unsupported.")
    for item in files.get('excluded', []):
        parts.append(f"Excluded: {_text(item.get('path'))} — {_text(item.get('reason'))}.")
    categories = coverage.get('standards', {}).get('owaspTop10', {}).get('categories', [])
    by_id = {c['id']: c for c in categories}
    rows = []
    for i in range(1, 11):
        key = f'A{i:02}:2025'; c = by_id.get(key, {})
        rows.append(f"| {key} | {_text(c.get('name', ''))} | {human_label(c.get('state', 'unknown'))} | {_text(c.get('reason'))} |")
    parts.extend(['### OWASP Top 10:2025', 'Common web application risk categories and the review work completed for each.',
                  '| Category | Name | Review state | Reason |\n|---|---|---|---|\n' + '\n'.join(rows)])
    for unit in coverage.get('units', []):
        parts.append(f"- {_text(unit.get('unitId'))}: {human_label(unit.get('state', 'unknown'))} — {_text(unit.get('reason'))}")
    for detector in coverage.get('detectors', []):
        parts.append(f"- Detector {_text(detector.get('detector'))}: {_text(detector.get('status'))} — {_text(detector.get('error'), 'No error recorded')}")
    for worker in coverage.get('workers', []):
        parts.append(f"- Review worker {_text(worker.get('attemptId'))}: {_text(worker.get('status'))}")
    for f in findings:
        parts.extend([f"## {_text(f.get('title'))}", _text(f.get('summary'))])
        taxonomy = f.get('taxonomy', {})
        details = []
        for key, label in [('cwe', 'Weakness type (CWE)'), ('owasp', 'Web risk category (OWASP)'), ('asvs', 'Application verification control (ASVS)')]:
            details.append(label + ': ' + ', '.join(taxonomy.get(key, [])))
        parts.append('Details — ' + '; '.join(details) + '. Evidence: ' + human_label(f.get('evidenceState', 'unknown')) + '.')
        parts.extend(['### Root cause', _text(f.get('rootCause')), '### Attack path'])
        attack = f.get('attackPath', {})
        parts.append('\n'.join(f'{i}. {_text(step)}' for i, step in enumerate(attack.get('steps', []), 1)) or 'No steps recorded.')
        parts.append('Assumptions:\n' + _bullets(attack.get('assumptions', [])))
        parts.append('Existing controls:\n' + _bullets(attack.get('controls', [])))
        parts.append('### Evidence')
        for evidence in f.get('codeEvidence', []):
            code = evidence.get('code', '')
            # A source excerpt may itself contain backticks; use a longer fence.
            fence = '`' * max(3, 1 + max((len(m.group()) for m in re.finditer(r'`+', code)), default=0))
            parts.append(f"{_text(evidence.get('label'))} — {_text(evidence.get('path'))}:{evidence.get('startLine', '?')}\n\n"
                         + fence + '\n' + code + ('' if code.endswith('\n') else '\n') + fence + '\n\n' + _text(evidence.get('explanation')))
        if not f.get('codeEvidence'):
            parts.append('No source excerpts were recorded; the source evidence is a proof gap.')
        parts.extend(['### What could make this wrong', _bullets(f.get('counterEvidence', [])),
                      '### Proof gaps', _bullets(f.get('proofGaps', [])), '### Validation'])
        validation = f.get('validation', {})
        parts.append(f"{human_label(validation.get('status', 'NOT_RUN'))} — {_text(validation.get('summary'), 'No static checks recorded.')}")
        parts.extend(['### Severity', f"{human_label(f['severity']['level'])} — {_text(f['severity'].get('rationale'))}",
                      '### Fix', _text(f.get('remediation', {}).get('summary')), 'Regression tests:', _bullets(f.get('remediation', {}).get('regressionTests', []))])
    parts.append('## Chains')
    for chain in chains_doc.get('chains', []):
        parts.extend([f"### {_text(chain.get('title', chain.get('chainId')))}", _text(chain.get('summary')),
                      human_label(chain.get('disposition', 'candidate_chain')) + ('; conditional.' if chain.get('conditional') else '.')])
        for edge in chain.get('edges', []):
            parts.append(f"{_text(edge.get('from'))} → {_text(edge.get('to'))} ({_text(edge.get('state'))})\n\nAssumptions:\n" +
                         _bullets(edge.get('assumptions', [])) + '\n\nDefeating controls:\n' + _bullets(edge.get('counterEvidence', [])))
    for broken in chains_doc.get('broken', []):
        parts.append('Blocked chain: ' + _text(broken.get('defeatedBy')))
        edge = broken.get('edge', {})
        if edge:
            parts.append(f"{_text(edge.get('from'))} → {_text(edge.get('to'))}\n\nAssumptions:\n" +
                         _bullets(edge.get('assumptions', [])) + '\n\nDefeating controls:\n' +
                         _bullets(edge.get('counterEvidence', [])))
    if not chains_doc.get('chains') and not chains_doc.get('broken'):
        parts.append('No chains recorded.')
    retained = list(findings_doc.get('retained', [])) + [f for f in findings_doc.get('findings', []) if f.get('evidenceState') not in {'source_supported', 'runtime_confirmed'}]
    parts.extend(['## Retained and rejected candidates', f'{len(retained)} candidates retained outside the reported findings.'])
    for f in retained:
        reason = f.get('reason') or f.get('rejectionReason') or f.get('summary') or 'No reason recorded.'
        parts.append(f"- {_text(f.get('title', f.get('candidateId')))}: {human_label(f.get('evidenceState', 'candidate'))} — {_text(reason)}")
    gaps = coverage.get('gaps') or ([f"The scan ended with status {manifest.get('status', 'unknown')}; not all requested review work was established as complete."] if incomplete else [])
    parts.extend(['## Limitations', _bullets(gaps, 'No coverage gaps were recorded.'),
                  'Source review alone does not establish runtime exploitability. Validation that was not performed is marked NOT RUN.'])
    return '\n\n'.join(parts) + '\n'
