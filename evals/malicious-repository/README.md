# Hostile-repository canaries (Task 14)

Executable fixture builders live in `tests/integration/test_hostile_repository.py`.
Everything hostile is generated under pytest `tmp_path`: **no committed symlinks,
FIFOs, devices, secrets, scanner binaries or archive bombs**. Inputs use synthetic
sentinels only. Tests are offline and use the real `SecurityService` except the
focused `/dev/null` reader and subprocess-output boundary probes.

Run from the repository root:

```sh
python -m pytest -q -p no:cacheprovider tests/integration/test_hostile_repository.py
```

## Cases and expected outcomes

| Builder/canary | Expected outcome |
|---|---|
| Instruction text in AGENTS/SECURITY/README, source comments and SARIF messages | No execution or policy changes; scanner messages are controlled labels, source snippets remain inside longer Markdown fences |
| Symlinks, FIFOs, oversized file | Recorded exclusions; cannot seal complete even when every remaining review unit is closed |
| Device descriptor | `/dev/null` rejected as non-regular before reading |
| Hardlink to external file | Link count recorded; target and external file unchanged |
| Symlink swap during excerpt verification | Rejected candidate; external sentinel never persisted |
| Hardlink swap restored before second snapshot check | Exact bytes used for evidence must match the inventoried SHA-256 |
| Detector symlink check/open race | Descriptor-relative no-follow read; never open the external file |
| Traversal, doubled slash, absolute, case and Unicode-normalization aliases | No borrowed inventory identity; candidate rejected |
| Very long line, malformed UTF-8, NUL bytes | Explicit failed/truncated detector lane and partial bundle |
| Zip/tar high-compression content and nested archive | Never extracted; opaque/unsupported content recorded, coverage partial |
| Foreign scan packet, candidate ID, attempt ID | Rejected; second scan's candidates unchanged |
| Unknown role, malformed IDs, oversized/compacted worker summaries | Contract rejection; summaries never confer review coverage |
| Token crossing read chunk; multiline PEM; isolated excerpt line | No secret literal in any data file, including SQLite/WAL/SHM |
| Output cap splitting credential | Unfinished output line discarded before persistence |
| Fake executable exits 0 with garbage/outside locations/failed invocation/oversized SARIF | Receipt failures or gaps; review closure cannot override incomplete scanner evidence |
| Finalizer lease contention and exception on third artifact write | No sealed half-bundle; verification fails; cancel/resume/retry works |
| Late completion after seal | `SealedError`, bundle bytes unchanged |
| Provider/model changes in host-owned attempts | Recorded as metadata, not coverage authority |

The fixture guard hashes regular-file bytes, relative paths, types and modes;
it records symlink targets without following them and never reads FIFOs/devices.
Simulated attacker swaps are restored before the guard runs. Coverage canaries
explicitly close unrelated file/worker/standards units so missing baseline work
cannot mask a false-complete defect.

## Known strict xfail

`test_provider_fallback_is_present_in_sealed_runtime`: host-owned attempt metadata
persists, but sealed `runtime.fallbacks` is always empty. The worker contract has
no trusted per-attempt runtime/fallback transport. This needs host lifecycle
integration rather than accepting untrusted worker metadata or guessing provider
changes from process environment; it is deliberately **not** claimed complete.

## Test-forced production changes

- `orchestration/coverage.py`: unsafe exclusions and detector truncation/errors
  prevent completeness. Justified by exclusion closure, long-line and outside-path
  fake-detector tests.
- `detectors/secrets.py`: skipped binary/undecodable content is an explicit failed
  receipt; no-follow bounded reads replace check-then-open. Justified by malformed
  encoding/NUL/archive cases and detector symlink race.
- `detectors/sarif.py`: declared unsuccessful invocations fail parsing even when
  the executable exits zero. Justified by the lying fake-detector case.
- `orchestration/worker_protocol.py`: supplied candidate IDs must match computed
  scan-bound identity. Justified by cross-scan contamination test.
- `target/excerpt.py` and `orchestration/worker_protocol.py`: optional expected file
  digest is checked on the exact bytes excerpted. Justified by the transient
  hardlink swap (before/after inventory checks alone were insufficient).
- `detectors/base.py`: drop incomplete trailing output lines on truncation/timeout
  before redaction and persistence. Justified by the credential output-cap test.

These canaries do not establish arbitrary-language secret reconstruction or
native Windows reparse-point safety. The secure target reader explicitly rejects
platforms without its required POSIX no-follow/descriptor primitives.
