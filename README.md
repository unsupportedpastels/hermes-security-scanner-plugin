# hermes-security

A Hermes plugin for reviewing local repositories and keeping findings, evidence,
validation receipts, and coverage together. Standard, Deep, and Diff review modes
share a Python/SQLite core. Reports distinguish code-supported findings from
issues confirmed by a test, and keep rejected or inconclusive candidates visible.

This repository is under development. The scaffold alone does not run scans;
service registration, CLI, and workbench modules must be present before use.
`docs/CONTRACT.md` defines the implementation contract.

## Install from a local checkout

Requires Python 3.11+ and Hermes 0.21.5 or later. The Python core uses only the
standard library. Choose the intended profile's `HERMES_HOME` first.

```sh
export HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
mkdir -p "$HERMES_HOME/plugins"
ln -s /absolute/path/to/hermes-security "$HERMES_HOME/plugins/hermes-security"
hermes plugins enable hermes-security
```

Restart Hermes after enabling. Do not overwrite an existing installation without
checking where it points. The native manifest uses JSON syntax (valid YAML).
Commands are registered in Python; this Hermes manifest format has no command,
dashboard, or desktop declaration keys.

The optional Desktop workbench is a separate, opt-in half. Once
`desktop/plugin.js` and `dashboard/manifest.json` are available:

```sh
mkdir -p "$HERMES_HOME/desktop-plugins/hermes-security"
cp -R /absolute/path/to/hermes-security/desktop/. "$HERMES_HOME/desktop-plugins/hermes-security/"
```

Enable the Desktop plugin explicitly in the app (its metadata must use
`defaultEnabled: false`). Keep the Python plugin installed for the dashboard API.
On a remote host, repository paths refer to that host, not the client computer.

## Interfaces

Agent tools in the `security` toolset:

- `security_scan_start`
- `security_scan_get`
- `security_scan_checkpoint`
- `security_scan_submit_worker_result`
- `security_scan_import_detector_results`
- `security_scan_record_validations`
- `security_scan_record_chains`
- `security_scan_finalize`
- `security_scan_cancel`
- `security_scan_export`

The `/security` slash command supports `status`,
`authorize-validation <scan> <origin> [--actions ..] [--minutes N]`, and
`revoke <grant>`. Only user commands/CLI can grant active validation; agent tools
cannot authorize themselves.

The service also exposes `hermes security ...` and
`python -m hermes_security ...` for terminal and subagent use. Consult their
`--help` output once the service is installed for available subcommands.
Exports include Markdown, JSON, CSV, and SARIF.

## Safety levels

- **static** (default): treat target content as untrusted data; do not execute
  target code, write into its tree, or probe live services.
- **local-safe**: requires explicit `allowLocalValidation` consent. Run bounded
  checks in a disposable copy. Network isolation may be best-effort when OS
  isolation is unavailable; check the receipt rather than assuming a sandbox.
- **active-authorized**: requires a time-limited user grant for exact origins,
  actions, and request limits. Off-origin redirects are refused.

A finding becomes runtime-confirmed only with a passed receipt, paired positive
and negative controls, and a non-static validation level. Unrun tests are
`NOT_RUN`, not proof. Changes to target code remain a separate user action.

## Data and limitations

Scan state and artifacts stay under the active profile's
`$HERMES_HOME/plugin-data/hermes-security` (via `ctx.state.data_dir` in Hermes).
There is no hosted findings service or automatic ticket publication. Exports
are user-controlled. Local storage does **not** mean model analysis stays on
this computer: Hermes's configured provider may receive review context.
Optional external scanners have their own behavior and network requirements.

Secret values must not be stored in evidence or logs; only their type, location,
and one-way fingerprint are retained. Treat reports as sensitive regardless.
Sealed artifacts are immutable; local triage does not rewrite sealed evidence.

Missing scanners, incomplete worker results, and unreviewed code produce gaps.
Zero findings with partial coverage is not a clean bill of health. OWASP Top
10:2025 and ASVS 5.0.0 mappings record review coverage, not certification.
Model review can miss issues or misread code; verify conclusions and assumptions.
Deep work is bounded and resumable, not guaranteed to run through host restarts.

## Development and provenance

```sh
python -m pytest tests/plugin/test_manifest.py -q
python scripts/provenance.py
python scripts/provenance.py --check
hermes plugins validate .
```

Provenance regeneration needs the pinned upstream checkout. Use
`--source-root /path/to/codex-security` to override the research-checkout default.
Run regeneration after adapting a file, and `--check` before accepting changes.
See `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md` for legal attribution.
