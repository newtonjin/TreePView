# M0b — crate validation gate

Run on Windows 11 (build 26200), Rust 1.97.1 MSVC, **without elevation**.

Reproduce: `cargo run -p m0-gate`

## Verdict

| Crate | Verdict | Evidence |
|---|---|---|
| `evtx` 0.12.2 | PASS | 15,578 records, 0 errors, 20.1 MiB in 1.09 s |
| `prefetch-core` 0.1.1 | PASS | 3/3 real `.pf`; SCCA v31, run count and file list correct |
| `prefetch-forensic` 0.4.2 | PASS | `audit()` produced 1 anomaly across the 3 samples |
| `ntfs-core` 0.9.6 | PASS | Synthetic VBR parsed; `carve_mft_entries` does not panic on garbage |
| `ntfs-forensic` 0.8.3 | PASS | `audit_record` survives an invalid entry |
| `rusqlite` 0.40 | PASS | Bundled SQLite 3.53.2, FTS5 available, clean blob round-trip |
| `zstd` 0.13 | PASS | 160× on EVTX-shaped JSON |
| `sysinfo` 0.39 | PASS | 326 processes, 324 with parent PID (tree can be built) |
| `ntfs-core::NtfsFs` | API-ONLY | Correctly rejects non-NTFS input; volume read needs elevation |
| `vshadow` 0.2.0 | API-ONLY | Correctly rejects a non-VSS buffer; real snapshots need elevation |
| `notatin` 1.0.1 | API-ONLY | Builder links and errors correctly on a missing hive; hives need elevation |

No artifact needs a homegrown parser. The three API-ONLY results are a privilege limit of this environment, not of the crate, and will be exercised in M3 under elevation.

These parsers are **not all wired into `tpv collect`**. Live collect now takes Prefetch, scheduled tasks and image hashes (`disk_artifacts`, skip with `--no-disk`). `$MFT` / VSS / hives stay gated. See [usage.md](usage.md#not-collected-yet).

## Issues that required action

**`notatin` declares `nom = ">= 6"`.** Unbounded range: Cargo resolves nom 8, whose `Parser` is no longer callable as a function, and the crate does not compile. Declaring `nom = "7"` on the workspace does not help — Cargo keeps both versions because the requirements do not unify. The fix is a precise pin in `Cargo.lock`:

```
cargo update -p nom@8.0.0 --precise 7.1.3
```

`Cargo.lock` is versioned for this reason. A broad `cargo update` that reintroduces nom 8 breaks the build; the command above is the fix. Fallback if `notatin` goes unmaintained: `winreg-core` 0.2.1, from the same ecosystem as `ntfs-core` and `vshadow`.

**`vshadow` prints to stdout.** The crate emits `[VSS DEBUG] First 4 bytes: ...` during parsing. In a forensic collector that is unacceptable: it pollutes output, can leak disk content into a log, and bypasses `tracing`. Before M3, either capture/redirect stdout around `vshadow` calls, or vendor the crate and remove the print.

**`binrw` 0.11.3 emits a future-incompatibility warning.** Transitive via `notatin`. Does not break today; watch it.

## Consequence for the data model

`evtx` returns `jiff::Timestamp` with `as_nanosecond() -> i128`. That confirms the plan to normalize everything to UTC nanoseconds: the highest-volume source already delivers that precision without a lossy intermediate conversion.
