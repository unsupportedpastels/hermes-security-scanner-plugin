# Evaluation and provisional release gates

These are offline canaries, **not measured model discovery quality**. Passing them
means the checked deterministic boundaries behaved as expected; it is not a
release-quality claim. No model was called to generate this report.

## Run

From the repository root, using the environment with pytest installed:

```sh
/home/mark/.hermes/hermes-agent/venv/bin/python scripts/run-evals.py --deterministic
/home/mark/.hermes/hermes-agent/venv/bin/python -m pytest -q -p no:cacheprovider
```

`--deterministic` is the default. Output is one JSON object followed by a Markdown
table. Any **run** gate failure produces a nonzero exit. NOT RUN is not PASS and
does not independently change the exit status. The harness uses stdlib Python;
its contract-test subprocess needs pytest, just like the project's tests. No
external scanner, remote service, model credential, or network access is needed.
Local loopback/disposable validation in the existing contract suite is retained.

### What the offline gates measure

- **Contract tests:** applicable, non-skipped test results from the real test
  suite. The harness excludes its own test file to prevent recursion; the separate
  full-suite command includes it. JSON includes counts, skips, command and captured
  output. Expected failures are shown in pytest output, not silently declared
  fixed. A green contract fraction does not validate skipped/expected-failure
  scenarios.
- **Citations:** real `SecurityService` submissions accept pinned source excerpts,
  compute the stored digest, and reject forged snippets, foreign paths and bad
  lines. The reported fraction is passing canary tests, not a population estimate
  of citations in model output.
- **Execution claims:** an agent-supplied passed local runtime receipt is rejected;
  static checks do not become runtime confirmation.
- **Isolation:** scan/packet/snapshot binding, cross-scan schema references and
  profile isolation are exercised against the real service/storage code.
- **Truncation:** oversized worker fields, bounded SARIF and inventory limits;
  inventory truncation and truncated detector output must leave explicit gaps.
  This is bounded canary coverage, not proof that every possible pagination or
  chain budget is exhaustive.
- **False-clean:** unsupported detector integration, failed/unknown/unavailable
  receipts and truncated successful output are tested. The direct coverage matrix
  first proves the otherwise-complete baseline, so an unrelated gap cannot mask a
  detector failure.
- **Chains:** runs the existing, unchanged `scripts/eval_chains.py` over all 12
  existing fixtures. Precision >=95%, recall >=85%, invented edges =0. The existing
  runner additionally requires exact fixture agreement; no chain implementation
  or fixture is copied or rewritten.
- **Dedup:** four adversarial source-reference sets check that same CWE alone or
  same anchor with different rule does not merge, duplicate observations merge
  only along gold-allowed edges, and rejected/inconclusive sources remain counted.
  Conservation must be 100%; unexpected merges must be zero. These do not certify
  arbitrary natural-language remediation-subsumption judgments.
- **Severity policy:** four independently labeled chain fixtures exercise actual
  code-computed uplift, non-uplift and conditional-path severity. They do not
  measure whether a model initially assigned primitive severities correctly.

## Corpus and model scoring (NOT RUN)

`evals/discovery/gold.json` has 26 synthetic review cases: vulnerable/fixed siblings
for 13 families: tenant access control, business-state transitions, SQL injection,
SSRF, traversal, deserialization, upload, cryptographic token generation,
exceptional-condition fail-open, secrets, SCA, IaC and CI/supply chain. The tenant
matrix adds same-tenant, cross-tenant and anonymous expectations. Files are under
`tests/fixtures/{vulnerable,fixed}/`. Never execute these inputs. The credential is
explicitly fake, domains are `.invalid`, and the SCA library/advisory are fictional;
these are reasoning fixtures, not assertions of actual package vulnerabilities.
The code fixtures are mainly Python plus HCL/YAML/dependency text; this small
corpus does not establish broad framework/language coverage.

These are public development fixtures, **not a genuinely blind holdout**. For a
blind run, have a separate evaluator provide isolated fixture copies without gold,
family/variant labels or neighboring sibling files. Scan each copy independently
with full-directory scope, no Git revision, no execution, and explicit provider
and model metadata. Keep gold hidden from the scanning model. A real independent
holdout and human root-cause adjudication are still required before release.

```sh
/home/mark/.hermes/hermes-agent/venv/bin/python scripts/run-evals.py --score-bundles /path/to/sealed-bundles
```

Supply `/path/to/sealed-bundles/index.json`:

```json
{
  "runs": [{
    "runId": "run-1",
    "provider": "actual-provider",
    "model": "actual-model",
    "records": [{
      "caseId": "access-control-vulnerable",
      "status": "ok",
      "bundle": "run-1/access-control-vulnerable"
    }]
  }]
}
```

This example is only the index shape, not a completed scan or measured score.
Every expected case should have a record. `status` is `ok`, `abstained`, `error`,
`deferred` or `unsupported`; non-ok records can omit `bundle`. If a partial scan
reports findings, provide its bundle so those findings are still graded. Missing
cases are counted separately; all their gold roots remain missed. The scorer
verifies seals, scan references, provider/model metadata, and snapshot equality
with the fixture bytes. Reusing a sealed scan across runs is an error. Partial
bundles are counted as deferred, not completed. Invalid bundles are errors, not
clean scans. A separate completed-case-coverage gate requires all expected cases,
including fixed siblings, to complete; leaving out negatives cannot earn a pass.

### Matching and denominators

A finding matches a gold root by **exact `ruleId` + `identity.anchor`**. Gold IDs
are an evaluation vocabulary; independently adjudicate any alias normalization
before scoring (do not relabel after observing scores). There is no fuzzy title,
CWE-only matching, or LLM judge. Duplicate reports are false positives after the
first one-to-one match. Findings on fixed siblings are false positives.

- Precision = matched reports / all reported findings; no reports gives `null`
  and fails the precision gate, never an automatic 100%.
- Recall = matched gold roots / **all** expected roots, including missing,
  abstained, errored, deferred and unsupported cases.
- High/Critical recall has all gold High/Critical roots as its denominator.
- Severity exact and within-one-band divide correctly graded matched roots by
  **all gold roots**, not only discovered findings. Bands in order are
  informational, low, medium, high, critical. Missed roots receive no credit.
- High/Critical precision = correctly matched gold High/Critical reports / all
  reports labeled High/Critical. Empty denominator is `null`.
- Retained/inconclusive candidates are reported as `retained`, never counted as
  confirmed findings. Case abstentions/errors/deferred/unsupported/missing are
  separately reported; they do not disappear from recall denominators.

Thresholds: precision .95, recall .85, High/Critical recall .95, exact severity .85,
within-one-band .95 and High/Critical precision .95. These remain provisional.

### Five-run agreement (NOT RUN)

```sh
/home/mark/.hermes/hermes-agent/venv/bin/python scripts/run-evals.py --score-bundles /path/to/five-run-bundles
```

Use exactly five independently collected runs for each identical provider/model
pair in the same index format. Verdict agreement is the fraction of all expected
cases where all five completed runs agree positive versus negative (>=.95).
Root-set agreement is the mean of ten pairwise Jaccards per case, averaged across
all cases (>=.90). Empty/empty sets have Jaccard 1; any missing/non-ok run makes
that case's agreement zero. Agreement is not correctness; discovery gates run
alongside it. No assertion of independence can be proved from artifacts alone.

### Paired upstream comparison (NOT RUN)

```sh
/home/mark/.hermes/hermes-agent/venv/bin/python scripts/compare-upstream.py --pairs /path/to/paired-bundles/pairs.json
```

Index shape:

```json
{"pairs":[{"caseId":"access-control-vulnerable","upstream":"upstream/case-1","hermes":"hermes/case-1"}]}
```

The upstream side must be a completed `codex-security` v1 scan and is loaded
through `hermes_security.compat.codex_import`; Hermes must be a verified completed
bundle. Both must identify the same expected isolated fixture snapshot, using the
Hermes content snapshot digest in target metadata for comparison eligibility.
Do not silently fill upstream proof gaps: importer-retained findings stay retained.
An upstream format without comparable snapshot metadata is an input error, not
proof of parity. Imported upstream input is not falsely described as byte-identical
or a newly executed scan. No supplied pairs means NOT RUN with no invented scores.

The paired statistic is exact root-set verdict correctness per repository case.
The one-sided 95% distribution-free Hoeffding lower confidence bound for mean
Hermes-minus-upstream correctness must exceed -.02, with no new High/Critical
miss. All expected pairs must be present and valid. Cases are the sampling unit;
findings in one case are not treated as independent samples. This tiny development
corpus will generally be unable to establish a two-point noninferiority bound;
collect a larger genuinely independent evaluation set before making that claim.

## Latest actual offline execution

Full JSON and captured subprocess evidence: [`evals/latest-deterministic.txt`](evals/latest-deterministic.txt).
The table below is pasted from that execution, not a proposed outcome.

Gate | Threshold | Measured | Status
--- | --- | --- | ---
deterministic-contract-tests | 100% executed non-skipped tests | 1.0 | PASS
citation-resolution-and-forgery-rejection | 100% executed non-skipped tests | 1.0 | PASS
zero-fabricated-runtime-claims | 100% executed non-skipped tests | 1.0 | PASS
zero-cross-scan-contamination | 100% executed non-skipped tests | 1.0 | PASS
no-hidden-truncation-input-canaries | 100% executed non-skipped tests | 1.0 | PASS
no-false-clean-unavailable-detectors | 100% executed non-skipped tests | 1.0 | PASS
chain-precision | 0.95 | 1.0 | PASS
chain-recall | 0.85 | 1.0 | PASS
chain-inventedEdgeCount | 0 | 0 | PASS
zero-false-clean-failed-detectors | 0 | 0 | PASS
zero-hidden-inventory-truncation | 0 | 0 | PASS
dedup-source-conservation | 1.0 | 1.0 | PASS
dedup-invalid-merges | 0 | 0 | PASS
code-computed-chain-severity | 1.0 | 1.0 | PASS
blind-discovery-and-model-severity | — | — | NOT RUN: python scripts/run-evals.py --score-bundles /path/to/sealed-bundles
five-run-provider-agreement | — | — | NOT RUN: python scripts/run-evals.py --score-bundles /path/to/five-run-bundles
paired-upstream-comparison | — | — | NOT RUN: python scripts/compare-upstream.py --pairs /path/to/paired-bundles/pairs.json

The concurrent hostile-repository suite currently includes one expected failure
for trusted per-attempt provider/fallback lifecycle metadata. The captured pytest
output makes that limitation visible; it is not resolved by this eval harness.
Model discovery, model severity, five-run agreement and paired upstream parity
remain **NOT RUN**. No production-code changes were made by this task.

Final separate full-suite command returned:

```text
436 passed, 5 skipped, 1 xfailed in 17.85s
```
