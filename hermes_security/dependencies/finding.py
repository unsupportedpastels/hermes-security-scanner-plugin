"""One aggregate finding for the dependency check, rated at the worst severity it contains.

Every package with published advisories and every runtime past end of life goes into a
single finding, so the Workbench shows dependency risk next to reviewed findings instead
of only in report.md. Two hundred low and medium packages make a medium finding, not
two hundred findings.

An advisory says a pinned version is affected, not that this code reaches the affected
behaviour. The lockfile supports the version claim, so the finding is source_supported;
reachability is stated as a proof gap and confidence is low. Reviewers who trace a lead
to real use submit their own finding for it.
"""
from collections import Counter

from ..domain.models import promote_to_finding

RULE_ID = 'dependency.known-advisories'
ANCHOR = 'dependency-check'          # one finding per repository, so triage carries across scans
LISTED = 25                          # packages named in the finding; the report lists the rest
MAX_LOCATIONS = 20
_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
# Unrated advisories and runtimes past end of life count as low: real, but not graded by anyone.
_UNRATED = 'low'


def _level(lead):
    return lead.get('severity') if lead.get('severity') in _RANK else _UNRATED


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def _package_line(lead):
    advisories = lead.get('advisories', [])
    ids = ', '.join(a.get('id', '') for a in advisories[:3]) + (f' +{len(advisories) - 3} more' if len(advisories) > 3 else '')
    fixed = sorted({v for a in advisories for v in a.get('fixed', [])})[:3]
    rated = lead.get('severity') if lead.get('severity') in _RANK else 'unrated'
    return (f"{lead.get('name')} {lead.get('version')} in {lead.get('path')}: {rated}, "
            f"{len(advisories)} {'advisory' if len(advisories) == 1 else 'advisories'} ({ids})"
            + (f'; fixed in {", ".join(fixed)}' if fixed else '; no fixed version published'))


def build(receipt, *, scan_id, repo_key):
    """The aggregate finding for a completed check, or ``None`` when it found nothing."""
    if not receipt or receipt.get('status') != 'ok':
        return None
    leads = list(receipt.get('leads', []))
    runtimes = [r for r in receipt.get('runtimes', []) if r.get('status') == 'end_of_life']
    if not leads and not runtimes:
        return None
    levels = Counter(_level(l) for l in leads)
    levels.update(_UNRATED for _ in runtimes)
    worst = max(levels, key=lambda level: _RANK[level])
    total = receipt.get('vulnerablePackages', len(leads))
    by_level = ', '.join(f'{levels[k]} {k}' for k in _RANK if levels[k])
    leads.sort(key=lambda l: (-_RANK.get(_level(l), 0), l.get('path', ''), l.get('name', '')))

    parts = []
    if leads:
        parts.append(f"{_plural(total, 'package')} of {receipt.get('packages', total)} pinned in "
                     f"{_plural(len(receipt.get('sources', [])), 'lockfile')} have "
                     f"{receipt.get('advisories', 0)} published advisories")
    if runtimes:
        parts.append(f"{_plural(len(runtimes), 'declared runtime')} past end of life")
    summary = (' and '.join(parts) + f'. The worst of them is rated {worst}. An attacker who can drive input '
               'into an affected package function could exploit the published weakness; whether this code '
               'calls those functions was not checked.')

    lines = [_package_line(l) for l in leads[:LISTED]]
    if len(leads) > LISTED:
        lines.append(f'{len(leads) - LISTED} more packages are listed in the Dependency check section of report.md.')
    if receipt.get('truncated'):
        lines.append('The advisory list was truncated by the check; not every affected package is named.')
    lines += [f"{r.get('runtime')} {r.get('declared')} ({r.get('path')}): release line {r.get('cycle')} "
              f"reached end of life on {r.get('eolDate')}; latest is {r.get('latest')}" for r in runtimes]
    root_cause = ('Lockfiles and runtime declarations pin versions with known security defects:\n- '
                  + '\n- '.join(lines))

    sources = sorted({l['path'] for l in leads if l.get('path')} | {r['path'] for r in runtimes if r.get('path')})
    tool = receipt.get('tool') or {}
    candidate = {
        'ruleId': RULE_ID, 'identity': {'anchor': ANCHOR},
        'title': f'Dependencies with known vulnerabilities (worst: {worst})',
        'summary': summary, 'rootCause': root_cause,
        'attackPath': {
            'source': 'Untrusted input handled by a third-party package',
            'sink': 'Vulnerable code inside a pinned dependency or end-of-life runtime',
            'steps': ['Find an application path that passes attacker input to an affected package function.',
                      'Send input crafted for the published advisory.',
                      'Trigger the defect inside the dependency with the privileges of this application.'],
            'controls': [],
            'assumptions': ['The affected functions are reachable from this code; not verified.',
                            'The pinned versions are the ones that ship at runtime.']},
        'severity': {'level': worst,
                     'rationale': (f'Rated at the most severe advisory among the affected packages ({by_level}). '
                                   'Advisories without a published rating, and runtimes past end of life, count as low.'),
                     'reachability': 'Not traced: depends on whether this code calls the affected functions',
                     'impact': 'Whatever each advisory describes, up to the worst rating above',
                     'likelihood': 'Higher for packages that handle network or user input',
                     'prerequisites': ['The vulnerable package code is reachable from an entry point']},
        'confidence': {'level': 'low',
                       'rationale': f"Versions come from the lockfiles, matched against {tool.get('name', 'the advisory database')} "
                                    f"{tool.get('version', '')}; reachability was not reviewed.".replace(' ;', ';')},
        'evidenceState': 'source_supported',
        'taxonomy': {'category': 'vulnerable-dependencies', 'cwe': ['CWE-1395'], 'owasp': ['A03:2025'], 'asvs': []},
        'locations': [{'path': p, 'startLine': 1, 'role': 'manifest'} for p in sources[:MAX_LOCATIONS]],
        'codeEvidence': [], 'counterEvidence': [],
        'proofGaps': ['Reachability of each affected package function was not traced.'],
        'validation': {'status': 'NOT_RUN', 'level': 'static', 'receiptIds': [],
                       'summary': 'Package versions matched against published advisories; no code path was exercised.'},
        'remediation': {'summary': 'Upgrade each listed package to a fixed version, starting with the highest rated, '
                                   'and move end-of-life runtimes to a supported release line.',
                        'regressionTests': ['Re-run the dependency check and confirm no advisories remain for the upgraded packages.']},
        'capabilities': {'preconditions': [], 'effects': []}, 'secret': None, 'diffAttribution': None,
        'source': 'dependency-check',
    }
    return promote_to_finding(candidate, scan_id=scan_id, repo_key=repo_key)
