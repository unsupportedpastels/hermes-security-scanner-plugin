# hermes-security

A Hermes plugin for reviewing local repositories and keeping findings, evidence,
validation receipts, and coverage together. Standard, Deep, and Diff review modes
share a Python/SQLite core. Reports distinguish code-supported findings from
issues confirmed by a test, and keep rejected or inconclusive candidates visible.

`docs/CONTRACT.md` defines the implementation contract.

## Install from GitHub

Requires Python 3.11+ and Hermes 0.21.5 or later.

```sh
hermes plugins install unsupportedpastels/hermes-security-scanner-plugin --enable
```

Restart Hermes afterwards. To update later, run the same command with `--force`.
For the Desktop workbench, copy the installed plugin's `desktop/` folder as
described below, using `$HERMES_HOME/plugins/hermes-security` as the source path.

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
`revoke <grant>`. Only direct user commands/CLI or confirmed Desktop clicks can grant active validation;
agent tools cannot authorize themselves.

The service also exposes `hermes security-review ...` and
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

### Using the Desktop page

Choose **+ Scan**, then one of:

- **Just read the code (safest)** — prepares a chat draft, as before.
- **Read the code and test bugs on this computer** — read the warning and check
  **I understand this will run commands from this code on my computer**, then
  **Create scan**. The scan is created without running code. Use **Open in chat**
  to review the code and prepare test steps without finishing the scan. Paste the
  agent's JSON list into **Test steps (paste from chat)**, inspect its commands,
  click **Test the bugs on this computer**, and confirm. This runs the existing
  bounded local-command runner and shows **Test results**, output, and cleanup.
- **Read the code and test my running app** — check
  **I understand this will send test requests to my running app** and **Create scan**.
  Under **Test the bugs**, enter your app address (scheme, host, and port only),
  minutes (1–240), and request limit (1–200), then click
  **Allow testing my running app** and confirm. The page shows
  **App testing: allowed** / **App testing: not allowed**, the address, expiry,
  and requests used. Use **Open in chat** to ask the agent to test this existing
  scan using the displayed permission ID. **Stop allowing app testing** confirms
  and revokes that permission; it cannot undo requests already sent.

Only the user's click gives permission. Starting a scan never executes test code
or sends requests. Local tests require another explicit click for every submitted
plan; an agent cannot reuse it to execute local commands. App tests may be executed
by the agent only within an existing, unexpired, unrevoked permission's scope and
request limit. Finish/seal the scan only after testing; finished scans cannot take
new results. Static scans gain no execution authority from these controls.

“On this computer” means the computer running Hermes, which may be a remote host,
not the Desktop client. A temporary copy and resource limits are **not** filesystem
isolation against harmful code. Network isolation can be best-effort. Run only
trusted, reviewed commands. No application is started automatically.

For CLI users, the unchanged equivalent is `start --safety-level local-safe
--allow-local`, then `validate --scan <id> --file <plans.json> --allow-local`.
The authenticated dashboard is also a user-authorization surface, not an agent
API. A confirmation field supplements host session authentication; it is not a
replacement for it. Never expose the plugin router without the host's auth.

## Data and limitations

Scan state and artifacts stay under the active profile's
`$HERMES_HOME/plugin-data/agent-plugin-hermes-security-974429e7` (Hermes's
`ctx.state.data_dir`; the dashboard and standalone CLI resolve the same folder).
`python -m hermes_security data-dir` prints it.
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
