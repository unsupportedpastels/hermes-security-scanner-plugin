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
- `security_scan_record_validations`
- `security_scan_record_chains`
- `security_scan_finalize`
- `security_scan_cancel`
- `security_scan_export`

The `/security` slash command supports `status`,
`authorize-validation <scan> <origin>`, and `revoke <grant>`. Agent tools cannot
give themselves permission to test a running app.

The service also exposes `hermes security-review ...` and
`python -m hermes_security ...` for terminal and subagent use. Consult their
`--help` output once the service is installed for available subcommands.
Exports include Markdown, JSON, CSV, and SARIF.

## Running a scan

In chat, just ask: *"scan this repo for security issues"*. Or choose **+ Scan** on
the Desktop **Security** page and fill in:

1. **Repository folder** — a folder on the computer running Hermes.
2. **What to scan** — **Full codebase** or **Recent changes** (uncommitted work, or
   your branch against the default branch; picked automatically).
3. **Deep scan** (optional) — slower, more thorough full-codebase passes.
4. **Run tests to confirm findings** (optional) — the agent writes and runs small
   reproductions with your normal toolchain, in a temporary copy of the repo.
5. **Only this folder** and **Extra context** (both optional).

Press **Start scan**; a ready-to-send chat draft opens. The agent builds a threat
model, reviews the in-scope code (see Standard vs deep below), checks each candidate against the code (and
with tests, if allowed), then traces whether an attacker can reach it. There is
nothing to install: the review is model reasoning. Vendored code, links, special
files and files over 8 MB are skipped and listed in the report.

The work is split by folder into areas sized to finish in one review, plus one
baseline reviewer that maps entry points and trust boundaries over the whole
scope. Up to 6 reviewers run at once.

**Standard vs deep.** A standard scan reads a small repository (under about 60k
lines) in full. In a larger one it reviews production code (source, config, CI,
IaC, migrations) and skips tests, fixtures, docs, examples, translations,
generated files, assets and lockfiles, unless one of them holds a committed
secret. Areas are ranked by what the code does (routes, request input, exec,
SQL, deserialization, auth, webhooks); every app or top-level folder gets its
riskiest area read first, then the riskiest of the rest, within a reading budget of 25%
of production code (at least 300k lines, at most 800k). At most two of the
riskiest areas get a second independent reviewer, and files a reviewer could not
finish get one more pass. Everything a standard scan skips is listed in the
report as excluded by design, with a reason. A deep scan reads every file,
adds more second reviews and allows up to three follow-up passes.

**Dependency check:** before the review starts, the scan checks your lockfiles
against published advisories with Google's
[osv-scanner](https://github.com/google/osv-scanner) and checks declared runtime
versions (Node, Python, Go, PHP, Ruby) against endoflife.date. The first scan
downloads a pinned osv-scanner release from GitHub, about 55 MB, refuses it unless
its SHA-256 matches the pin, and keeps it in the plugin's data folder. Package
names and versions are sent to api.osv.dev (and api.deps.dev for manifests
without a lockfile). Advisories are leads: a finding is reported only when the
review shows your code reaches the vulnerable behaviour. If the check cannot
run, the report says so and the scan is marked partial. To turn it off, set
`HERMES_SECURITY_DEPENDENCY_CHECK=off`. Networks that block GitHub can point
`HERMES_SECURITY_OSV_SCANNER` at an osv-scanner binary installed by an admin.

**If a scan stops halfway:** the plugin remembers where every scan is, so a new
turn (or **Continue scan** on the scan's page) picks up at the right step:
start the review packets that have no saved result, check the candidates, trace
attack paths, then finish. A reviewer that ends without saving its result is
handed out again.

It can also continue on its own. When a chat turn ends and its scan still has
work to do, the plugin queues one "Continue security scan" message in that chat.
It never does this after you press Stop, and after 3 continues that make no
progress it pauses and shows **Paused — needs attention** until you continue it.
This needs a one-time switch, because it lets the plugin send messages into your
chat:

```bash
hermes config set plugins.entries.hermes-security.allow_gateway_injection true
```

Without it, a stalled scan shows **Paused — could not continue automatically**
and waits for **Continue scan** or a message from you. A turn that fails with a
model provider error does not trigger a continue; send any message to resume.

**Testing a running app (optional):** on an open scan, enter its address under
**Confirming findings** and click **Allow testing this app** (or run
`/security authorize-validation <scan> <origin>`). The agent may then send up to 200
requests to that exact address for an hour; same-site redirects are followed,
other sites never are. **Stop** revokes it.

What stays in place: repository text is treated as data, never instructions;
secrets are redacted to a fingerprint; Git hooks/filters never run; findings cite
exact code from the snapshot; finished reports are sealed. Tests run as you, in a
temporary copy, with credential-looking environment variables removed — that is
convenience, not a sandbox, so only enable tests for code you trust.

A finding becomes "Confirmed by test" only with a passing test and a matching
negative control. Unrun tests are `NOT_RUN`, not proof.

CLI equivalent: `python -m hermes_security start --path <repo> [--mode diff|deep] [--tests] [--context ...]`.

## Data and limitations

Scan state and artifacts stay under the active profile's
`$HERMES_HOME/plugin-data/agent-plugin-hermes-security-974429e7` (Hermes's
`ctx.state.data_dir`; the dashboard and standalone CLI resolve the same folder).
`python -m hermes_security data-dir` prints it.
There is no hosted findings service or automatic ticket publication. Exports
are user-controlled. Local storage does **not** mean model analysis stays on
this computer: Hermes's configured provider may receive review context.

Secret values must not be stored in evidence or logs; only their type, location,
and one-way fingerprint are retained. Treat reports as sensitive regardless.
Sealed artifacts are immutable; local triage does not rewrite sealed evidence.

Incomplete worker results and unreviewed code produce gaps.
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
