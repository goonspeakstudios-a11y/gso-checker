# gso-checker architecture (phase 1)

Binding contract for the builders. Spec: `GSO_Engine_Checker_Spec_v0.2.md`
(sha256 `4a70367e...e114e61`, same file as `E:\GSO_checker_addendum_A\SPEC_v0.2.md`).
Phase 1 = spec sections 1, 2, 3 (V01-V07), 7, 8 and the section-9 commands
`sources`, `compare`, `check` (version rules only), `install-gate`, `install`,
`uninstall`, `sheet export`, `sheet import`. NOT in phase 1: section 4 (scripts),
5 (data), 6 (logs), `watch`.

**The docstrings in `gso_checker/*.py` are part of this contract.** Where this file
and a docstring disagree, this file wins; fix the docstring in the same commit.
Do not rename or re-type anything listed here. Builders do not talk to each other:
if something is ambiguous, implement the narrowest reading that makes the tests pass
and note it in the commit message.

## 1. Layout and dependency order

```
gso_checker/
  model.py      enums, frozen dataclasses, exceptions, _utcnow/utc_iso/make_finding_id
  config.py     checker.toml -> Config, rules catalog, globs, `sources` inventory
  hashing.py    sha256, CRLF/LF classification
  manifest.py   zip/folder/overlay manifests, normalization, compose, V02/V07, backup inventories
  store.py      SQLite (schema in SCHEMA_SQL)
  memory.py     dependency fingerprints, cache reuse, workflow status
  history.py    V03 A-B-A, repo snapshot history
  compare.py    compare rows, V01/V04/V05/V06, uninstall-plan parser, run_version_checks/run_check/run_compare
  process.py    read-only process probe (only subprocess user)
  gate.py       install-gate (read-only)
  installer.py  install / uninstall (only writer under game_root)
  sheet.py      CSV/XLSX export, import
  report.py     roll-up, text/json rendering, the only console writer (emit)
  cli.py        argparse front end
  __main__.py   python -m gso_checker
```

Import direction (no cycles): `model` <- `config` <- `hashing` <- `manifest` <- `store`
<- `memory` <- `history` <- `compare` <- `process` <- `gate` <- `installer` <- `sheet`
<- `report` <- `cli`. (`report` may be imported by `compare`, `gate`, `installer`
for `rollup`/Report building; `report` itself imports only `model`.)

Suggested build order (each step has its own unit tests):
model -> config -> hashing -> manifest -> store -> memory -> history -> compare ->
process -> report -> gate -> installer -> sheet -> cli.

## 2. Invariants (all modules)

- **Normalized path**: install-relative to the mod folder (`<game_root>/mods/<mod_folder>`),
  `/` separators, original spelling. Matching always uses `normalized_path.casefold()`
  ("path key"). Game-root files outside the mod folder (only from `game-root` zips)
  are `@game/<member>` and are never installable in phase 1 (gate `mapping` FAILs).
- **sha256** is always over raw bytes. CRLF->LF normalization exists only to compute
  `ManifestEntry.eol_sha256` for text paths (`[policy] text_extensions`), used to
  classify `line-endings-only`.
- **Time**: only `model._utcnow()` (aware UTC). Stored/printed form `utc_iso()` =
  `YYYY-MM-DDTHH:MM:SSZ`. Report-file stamp `YYYYMMDDTHHMMSSZ`. Never `datetime.utcnow()`.
- **finding_id** = `make_finding_id(rule_id, profile_id, input_id, normalized_path, line)`
  = first 16 hex of sha256(`rule|profile|input|path.casefold()|line-or-empty`). One
  finding per (rule, input, path); whole-input findings use path `""`.
- `input_id`: the release id for release findings, `"live"` for V05.
- **UNKNOWN is never turned into PASS.** Waivers never change `Finding.result`.
- **Profiles**: everything is evaluated under `[checker] profile`. Releases of another
  profile are never compared (V03 groups by profile; `check` on such a release yields
  one UNKNOWN V02 'profile mismatch' finding and nothing else).
- **Logging**: `logger = logging.getLogger(__name__)`; no `print`. The CLI's final
  output goes through `report.emit(text, stream)` only. All output ASCII (`ascii_safe`).
- Specific exceptions only; no bare `except:`. Type hints on every def.

## 3. Data model (model.py)

Already declared in `model.py` (do not change field names/order/types):
`Verdict{PASS,FAIL,UNKNOWN,INFO}`, `Classification`, `Packaging{full,patch}`,
`PackagingRoot{game-root,mod-root,mod-parent}`, `WorkflowStatus{"",Open,Fixed,Waived,Not a bug,Engine}`,
`ProcessState`, `GateOutcome{ALLOW,REFUSE}`, `CacheState{cached,rechecked}`;
dataclasses `ReleaseSpec, RuleSpec, ManifestEntry, Manifest, ComparisonRow, AbaHit,
Finding, ReviewDecision, ReviewedFinding, Waiver, SourceStatus, ProcessInfo,
ProcessObservation, GateCheck, GateDecision, InstalledFile, InstallRecord, Report`;
exceptions `CheckerError` (base, CLI exit 3) and `ConfigError, PathEscapeError,
ProfileMismatchError, CompositionError, ImmutableRecordError, ConfirmationError,
GateRefusedError(decision), ForbiddenWriteError`.

`Finding` fields 1-16 are exactly spec section 2 line 64:
`finding_id, rule_id, profile_id, input_id, normalized_path, line, result, message,
observed_value, expected_value, source_file_or_log, source_line_or_offset,
source_sha256, rule_version, checked_at_utc, dependency_fingerprint`; extras
`blocking` (False for INFO / info-severity), `waivable` (from the rule), `cache_state`.

Builders implement only `_utcnow`, `utc_iso`, `make_finding_id` in model.py.

## 4. Module contracts (summary; docstrings carry the detail)

### 4.1 config.py
`load_config(path) -> Config` (tomllib; relative paths against the file's folder; does
NOT create or require any path to exist; `[eur_baseline] path = ""` -> None; `[game]
live_mod` default `root/mods/<mod_folder>`; `[checker] rules` default
`<project>/rules/rules_phase1.json`; `[policy]` defaults: block_extras false,
text_extensions `DEFAULT_TEXT_EXTENSIONS`; `[game] process_names` default
`DEFAULT_PROCESS_NAMES`). `release_by_id`, `load_rules(path) -> dict[str, RuleSpec]`,
`rule_applies`, `match_glob(path, pattern)`, `is_gso_owned(cfg, path)`,
`resolve_sources(cfg) -> list[SourceStatus]`. TOML keys: see `checker.example.toml`
(it is parsed by a test). `[[releases]]` keys: `id, path, profile, packaging,
packaging_root, parent (optional), sha256 (optional)`; `parent` is only used for
`packaging = "patch"`.

### 4.2 hashing.py
`sha256_bytes, sha256_file, is_text_path, eol_normalize, eol_sha256, classify`.

### 4.3 manifest.py
`normalize_member(member, packaging_root, mod_folder) -> str | None` (raises
`PathEscapeError`), `build_release_manifest(spec, cfg, rules) -> Manifest`
(non-composed; V02/V07 findings in `problems`, PASS rows when clean),
`build_tree_manifest(root, *, release_id, kind, profile_id, text_extensions, include)`,
`build_overlay_manifest(cfg)` (id `repo@<16hex content fp>`), `compose(patch, parent)`,
`composed_manifest(cfg, release_id, rules, cache=None)`, `read_release_bytes(cfg,
release_id, path)`, `by_key(manifest)`, `load_backup_manifests(cfg)`.
Content fingerprint (`releases.content_fp`, repo id) = sha256 over sorted lines
`"<path_key>\t<sha256>\n"`.

**Backup format** (written by installer, read by `load_backup_manifests`):
`<backups>/<backup_id>/inventory.json` =
`{"backup_id", "created_at_utc", "source_root", "release_id", "files": [{"normalized_path","sha256","size"}]}`
and bytes at `<backups>/<backup_id>/files/<normalized_path>`. Manifest id `backup:<backup_id>`.

### 4.4 compare.py - rules
- `compare_manifests(a, b) -> list[ComparisonRow]`.
- `rule_v01(repo, release, rule, checked_at, fp, path_key)` one finding per required repo path.
- `rule_v04(repo, release, history, rule, checked_at, fp, path_key)`: "different from repo",
  or "older than repo: equals repo snapshot <id> recorded <date>" only when a stored
  historical repo snapshot has the release's exact hash. Never ZIP timestamps.
- `rule_v05(live, repo, known_path_keys, cfg, rule, checked_at, fp)`: message contains
  `live, not in repo, not in any manifest`; INFO unless `block_extras`.
- `parse_uninstall_plan(text) -> UninstallPlan` (grammar in docstring; the real 0.5.4e
  `GSO_Uninstall.bat` must parse with `understood=True`).
- `rule_v06(release, baseline, backups, uninstall_text, cfg, rule, checked_at, fp, path_key)`.
  Candidates = release entries not GSO-owned and not `@game/`. No baseline -> UNKNOWN
  ("EUR baseline not configured"). Problems joined with `; ` in one finding.

### 4.5 history.py
`find_aba(manifests)` (oldest first; grouped by profile; absent releases skipped;
flag n when `sha[n] != sha[n-1]` and some `k < n-1` has `sha[k] == sha[n]`, first = largest
such k), `rule_v03(manifests, rule, checked_at)`, `record_repo_snapshot(store, repo)`,
`repo_history(store, profile_id, exclude_release_id)`.

### 4.6 store.py
`Store(db_path)` with the methods in the file. Schema: section 5.

### 4.7 memory.py
`dependency_fingerprint, set_fingerprint, cache_key, evaluate_cached, workflow_status,
active_waiver_ids`. Rules in section 6.

### 4.8 sheet.py
`SHEET_COLUMNS` = spec section 8 columns + `rule_version` after `source_sha256`.
`export_sheet(reviewed, out_dir, release_id) -> SheetExport` writes
`review_<release_id>.csv` always and `.xlsx` only if `openpyxl` imports (else
`note = XLSX_UNAVAILABLE_NOTE`, printed by the CLI). `read_sheet(path)`,
`import_sheet(path, store, *, imported_at_utc) -> ImportResult` keyed by
finding_id + source_sha256 + rule_version (never row number). Rows with empty Status,
or Status `Open` for a finding that has no decision yet, are skipped (no-op).

### 4.9 process.py
`parse_tasklist_csv`, `parse_powershell_paths_csv`, `parse_wmic_csv`, `default_runner`,
`observe(names, *, runner)`, `SystemProcessProbe`. `ProcessProbe` =
`Callable[[Sequence[str]], ProcessObservation]`; every gate/installer/cli function takes
the probe as a parameter so tests inject it. Failure to observe = `UNKNOWN`, never
`NOT_RUNNING`. Allowed argv[0]: `tasklist`, `powershell`, `wmic` only.

### 4.10 gate.py (read-only)
`evaluate_gate(cfg, release_id, *, probe, store, rules, waivers=()) -> GateDecision`
runs `run_version_checks(include_live=True)` then checks in `CHECK_ORDER`:

| check | PASS when | non-PASS |
|---|---|---|
| profile | release profile == `[checker] profile` == `[game] profile` == `[eur_baseline] profile`, baseline configured+exists, `game_root/exe` exists | mismatch FAIL; missing proof UNKNOWN |
| process | probe NOT_RUNNING | RUNNING FAIL (image, PID, path, time); UNKNOWN UNKNOWN |
| manifest | no open FAIL/UNKNOWN in V01-V05, V07 | FAIL; V01/V03/V04/V05 FAIL closable by a waiver with reason |
| backup | backups dir set, exists, outside game_root; every V06 PASS/INFO | V06 UNKNOWN -> UNKNOWN; FAIL -> FAIL |
| mapping | every entry inside live_mod, no `@game/`, no V07 problem, live_mod inside game_root | FAIL |
| waivers | every supplied waiver has reason + author | FAIL "waiver for <id> has no reason" |

ALLOW only if every check is PASS (or waived). Any UNKNOWN blocks. `manifest` also FAILs
(not waivable) when a ZIP of the release chain does not match its declared `sha256`;
`backup` is UNKNOWN when rule V06 is missing or inactive; `mapping` FAILs when
`live_mod` is the game folder itself.

### 4.11 compare.py - orchestrators
`run_version_checks(cfg, release_id, store, rules, *, include_live=True) -> VersionCheckResult`,
`run_check(...) -> Report`, `run_compare(...) -> Report`. Each rule unit goes through
`memory.evaluate_cached`; all inputs are re-hashed every run (cache never skips hashing).
Manifests recorded with `store.record_manifest` (immutable). `run_check` attaches
`memory.workflow_status` to each finding and sets `cached`/`rechecked` counts
(counted per finding). All store writes of one `run_version_checks` call share one
transaction (`Store.batch()`; re-entrant, rollback on error).

### 4.12 installer.py (only writer under game_root)
`install(cfg, release_id, *, confirm, probe, store, rules, waivers=())`:
confirm must equal the release id exactly -> gate must ALLOW -> backup every file to be
replaced into `<backups>/<install_id>/` and verify -> copy via temp file + `os.replace`
-> re-hash every installed file -> `store.record_install`. `uninstall(cfg, install_id, *,
confirm, probe, store)`: confirm must equal the install id; game must be NOT_RUNNING;
restore pre-existing files from the backup (verify sha256), delete files the install
created, remove created dirs that are empty, verify EUR originals against the baseline
if configured. Every write path passes `assert_inside(cfg.live_mod or cfg.backups, p)`.
Install id: `inst-<YYYYMMDDTHHMMSSZ>-<release_id>`. Before any write, the installer re-composes
the release and refuses unless every (path, sha256, size, member, source release) equals the
manifest the gate recorded; each copied byte string is hash-checked against that manifest.

### 4.13 report.py
`rollup, count_line, ascii_safe, render_finding, render_text, render_json,
write_report(report, reports_dir, stamp), emit(text, stream), findings_only`.

## 5. SQLite schema (store.SCHEMA_SQL, verbatim contract)

Tables: `profiles, releases, manifest_entries, findings, decisions, installs, cache`.

- `profiles(profile_id PK, description, created_at_utc)`
- `releases(release_id PK, profile_id FK, kind in release|repo|live|baseline|backup,
  source_path, source_sha256, content_fp, packaging, packaging_root, parent, ordinal,
  recorded_at_utc)` - **immutable**: re-recording the same id with a different
  `source_sha256`, `content_fp` or `profile_id` raises `ImmutableRecordError`; identical
  re-record is a no-op returning False.
- `manifest_entries(release_id FK, path_key, normalized_path, size, sha256, eol_sha256,
  archive_member, source_release_id, PK(release_id, path_key))` - immutable with its release.
- `findings(run_id, finding_id, ...all 16 Finding fields..., blocking, waivable,
  cache_state, command, recorded_at_utc, PK(run_id, finding_id))` - append-only.
  `run_id` = `<stamp>-<command>`.
- `decisions(decision_seq PK AUTOINCREMENT, finding_id, source_sha256, rule_version,
  dependency_fingerprint, status, reason, reviewer, reviewed_at, imported_from,
  imported_at_utc)` - append-only; latest per finding_id wins.
- `installs(install_id PK, release_id, profile_id, target_root, backup_id, backup_dir,
  installed_at_utc, status, post_check, record_json, updated_at_utc)` - only
  status/record_json/updated_at_utc may change.
- `cache(cache_key PK, rule_id, rule_version, profile_id, dependency_fingerprint,
  findings_json, verified_at_utc)` - one row per evaluation unit, replaced on recheck.

The db lives at `<data_dir>/checker.db` (outside the game folder). Exact DDL: `store.py`.

## 6. Caching and the dependency-fingerprint rule

A cached result is reused only if **rule id, rule version, profile and dependency
fingerprint** are all unchanged. `fingerprint = sha256(canonical JSON {rule_id,
rule_version, profile_id, inputs: sorted [[name, value]]})`; values are sha256s of the
freshly hashed inputs, `"absent"`, or `set_fingerprint(...)` of a set. Units and inputs:

| rule | unit | inputs |
|---|---|---|
| V01 | each repo path key | `release` = release sha or absent, `repo` = repo sha, `release_eol`, `repo_eol` (eol_sha256 or absent) |
| V02, V07 | `""` (whole release) | `zip` = release ZIP sha256 (patch: every ZIP in the chain, `zip:<id>`) |
| V03 | each path key present in the target | `seq` = set_fingerprint of `"<order>:<release_id>:<sha>"` over the same-profile releases up to the target |
| V04 | each repo path key | `release`, `repo`, `history` = set_fingerprint of `"<sha>:<latest snapshot id>:<date>"` over historical repo shas for that key, excluding the current snapshot AND every sha equal to the current repo sha (those cannot change the outcome; without this rule every new repo snapshot re-ran every V04 unit) |
| V05 | `""` | `live` = set_fingerprint of `"<key>:<sha>"` over owned live files, `repo_keys` = set_fingerprint of repo keys, `known_keys` = set_fingerprint of stored manifest keys |
| V06 | each candidate path key | `release` sha, `baseline` sha or `"not configured"`/absent, `backups` = set_fingerprint of `"<key>:<sha>"` over verified backup entries for that key, `uninstall` = sha of GSO_Uninstall.bat or absent, `original_src` = sha of the release's `GSO/originals/<path>` or absent |

Consequences the tests rely on: editing one repo file re-runs exactly the V01 and V04
units of that path; an unrelated edit never reopens a Fixed finding; a rule version bump
invalidates every unit of that rule. `Verified YYYY-MM-DD, unchanged` (date =
`checked_at_utc[:10]` of the reused finding) is printed only for findings whose
`cache_state` is `cached`.

Workflow status (`memory.workflow_status`): a decision is "still valid" when its
`rule_version` and `dependency_fingerprint` equal the finding's. Fixed + FAIL/UNKNOWN +
not valid -> Open (reopened). Waived/Not a bug/Engine + not valid -> Open (reopened,
"waiver expired"). Waived never alters `result`; non-waivable FAILs (V02, V06, V07)
stay blocking in the roll-up even when a sheet says Waived.

## 7. CLI

`python -m gso_checker [--config PATH] <command>`; config path: `--config`, else env
`GSO_CHECKER_CONFIG`, else `./checker.toml`. `cli.main(argv, *, probe=None, stdin=None,
stdout=None) -> int` (tests call it directly).

| command | does | exit |
|---|---|---|
| `sources` | `resolve_sources`; one body line per input: `<present/MISSING> <name> | <path> | <kind> | mtime <..> | sha256 <..|-> | <note>` | 0 all phase-1 inputs present, 1 a ZIP does not match its declared sha256, 2 a phase-1 input missing. Phase-2-only inputs (`repo_tools`) show `not configured (phase 2)` and never change the exit code |
| `compare --release ID` | `run_compare` | roll-up |
| `check --release ID [--all]` | `run_check` (V01-V07); `--all` also lists PASS | roll-up |
| `install-gate --release ID [--waivers FILE]` | `evaluate_gate`; waivers = FILE (JSON list of Waiver dicts) + valid Waived decisions in the store | 0 ALLOW, 3 REFUSE |
| `install --release ID [--confirm TEXT] [--waivers FILE]` | prompt `Type the release id to confirm: ` if no --confirm; `installer.install` | 0 post-check PASS, 1 partial, 3 refused/mismatch |
| `uninstall --install ID [--confirm TEXT]` | prompt `Type the install id to confirm: `; `installer.uninstall` | 0 uninstalled, 1 partial, 3 refused/mismatch |
| `sheet export --release ID [--out DIR]` | `run_check` then `export_sheet` into DIR (default `<data_dir>/reports`); body lists CSV path, XLSX path or the CSV-only note | 0 |
| `sheet import --file PATH` | `import_sheet`; body: `accepted <id> <status>` / `rejected row <n> <id>: <reason>` | 0 none rejected, 1 some rejected |

Exit codes: **0 PASS / ALLOW / success, 1 FAIL, 2 UNKNOWN, 3 usage error, config error,
confirmation mismatch, blocked (REFUSE)**. Roll-up mapping: PASS 0, FAIL 1, UNKNOWN 2.
`CheckerError` -> one `ERROR: <message>` line after the header, exit 3, no traceback.
argparse errors -> exit 3 (catch `SystemExit` from argparse).

## 8. Report format (spec section 9)

Every command writes `<data_dir>/reports/<stamp>_<command>.txt` and `.json` and prints
the same text:

```text
GSO CHECKER | profile: EUREX-1.5 | release: 0.5.4e
VERDICT: FAIL | 2 blocking | 1 unknown | 297 passed
Reason: The release differs from two required repository files.
cached: 0 | rechecked: 300

<body_lines>

FAIL V04 | script/eur40/eur40BattleHud.nut: release file is different from repo.
  path: script/eur40/eur40BattleHud.nut
  observed: 793712b5... | expected: 44d82eb8...
  evidence: E:/GSO_054/GSO_0.5.4e.zip!Divide_and_Conquer_EUR/script/eur40/eur40BattleHud.nut | sha256: 793712b5...
  status: Open
  Verified 2026-11-08, unchanged            (only when cached)

Full report: C:/.../reports/20261108T101500Z_check.txt
```

(Hashes are printed in full; shortened here.) `VERDICT: n/a` for commands without a
verdict (`sources`, `sheet`); release `-` when the command has no release. The Reason
is one plain sentence. Findings order: FAIL, UNKNOWN, INFO (PASS only with `--all`).
JSON = `render_json` (all Finding fields + status fields).

## 9. Write boundaries (enforced by A11/A12/A14 tests)

- `sources, compare, check, install-gate, sheet export/import` write only under
  `data_dir` (db + reports) and, for `sheet export --out`, the given folder. Never
  under `game_root`. ZIPs, overlay, baseline, live tree are opened read-only (`rb`).
- `install`/`uninstall` write only under `cfg.live_mod` and `cfg.backups`, only after
  the exact typed confirmation, only after the gate ALLOWs (install) or the probe says
  NOT_RUNNING (uninstall). Never M2EX/medieval2 executables, never outside the mod folder.
- The CLI refuses (exit 3) a `data_dir`, reports folder or `sheet export --out` inside `game_root`.
- Nothing launches, signals or kills a process. No network, no AI.

## 10. Decisions taken in phase 1 (not dictated by the spec)

1. Normalized paths are relative to the mod folder; game-root-only files become `@game/...` and are not installable.
2. `mod-parent` packaging root added; members outside `<mod_folder>/` in such a zip are V07 path escapes.
3. `parent` composes only for `packaging = "patch"`; for full zips it is informational (all real releases are full).
4. Patch deletions are not representable (no deletion markers in GSO zips); documented limitation.
5. Every repo overlay file except `[repo] not_installed` is "required" for V01/V04.
6. "Older" (V04) is proven only by repo snapshots this tool has recorded itself (no git history read in phase 1); prior releases never prove "older".
7. A-B-A skips releases where the path is absent; one hit per (path, returning release); first = latest matching older release.
8. Exact duplicate ZIP member = V02 FAIL; case-only collision or escape = V07 FAIL.
9. V06 candidates = release paths outside `gso_owned` globs; EUR ownership needs the baseline; missing baseline = UNKNOWN per file and gate `profile` + `backup` UNKNOWN.
10. V06 restoration is established statically from `GSO_Uninstall.bat` `copy /Y "GSO\originals\X" "X"` lines plus matching `GSO/originals/X` bytes; unknown bat lines -> UNKNOWN.
11. One V06 finding per path, multiple problems joined with `; ` (keeps finding_id stable).
12. V05 emits findings only for untracked owned files (no PASS rows); "known" = any stored manifest of the profile.
13. Sheet gets an extra `rule_version` column (needed for the import key).
14. Decisions are valid while rule version + dependency fingerprint match; Waived/Not a bug/Engine expire like Fixed when the input changes.
15. Gate waivers: CLI `--waivers` JSON file plus valid Waived sheet decisions; only V01/V03/V04/V05 FAILs are waivable.
16. Gate `profile` proof = declared `[game] profile` + exe present + configured baseline profile; no exe-hash identity in phase 1.
17. Install backs up into `<backups>/<install_id>/`; the install id doubles as the backup id.
18. Exit code 3 covers usage, config errors, confirmation mismatch and REFUSE.
19. (2026-11-09, V06 rule version 2) "original kept" = the baseline sha256 found in a checker backup
    OR shipped byte-identical under the release's `GSO/originals/`. A live mod already running GSO never
    yields EUR's bytes in an install backup, so backups alone could never satisfy V06 on BB1's machine;
    the release copy is exactly what `GSO_Uninstall.bat` restores. Restoration is still checked separately.
