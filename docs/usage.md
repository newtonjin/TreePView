# Using TreePView

Operator guide: collect a case on USB, verify it, open it. The artifact encyclopedia lives in **[artifacts.md](artifacts.md)**. Absence of something marked *not collected yet* means the collector did not ask for it — not that it was missing on the host.

## Two binaries

| Binary | Where | Role |
|---|---|---|
| `tpv.exe` | Examined Windows host, from USB | Live collect, memory-image ingest, `info` / `tree` / `verify` |
| `TreePView.exe` | Analyst workstation | Timeline, process tree, inspector, hunt, export |

Do not copy the repository onto the incident host. Take **`tpv.exe`** (and `HOW-TO.txt` if you want the field card). Keep **`TreePView.exe`** on the analysis PC. GitHub Releases ship both; rebuild locally with `bin\install.ps1`.

---

## Collect a live case

From external media (example `E:`):

```bat
E:\tpv.exe collect --out E:\
```

`--out` omitted or pointed at a **directory** writes `HOSTNAME-YYYYMMDDTHHMMSSZ.tpv`. `--out file.tpv` still names the file yourself.

The collector has no installer, no config file, and makes no network calls. Order of volatility: clock → network → processes → services / drivers / autoruns → image SHA-256, Prefetch, scheduled tasks → high-value event logs.

It **refuses to write onto the examined volume** unless you pass `--allow-local-write` (that flag contaminates `$MFT` / `$UsnJrnl` and is recorded in custody). Partial failures become gaps, not a crash. **Ctrl+C seals** whatever was gathered; `tpv verify` still works.

| Flag | Effect |
|---|---|
| `--allow-local-write` | Permit output on the examined volume. Recorded as contamination. |
| `--no-live` | Skip volatile state; host identity only. |
| `--no-evtx` | Skip Windows event logs (collected by default). |
| `--evtx-cap N` | At most N records per channel. Omit to ingest the whole log. |
| `--no-disk` | Skip Prefetch, scheduled tasks, and SHA-256 of process images. |
| `--pid N` | Repeatable. Restricts memory-region acquisition, not the live process list. |
| `--max-ram 512` | Collector resident-memory cap, in MiB. |

Elevation is optional. The collector prints **immediately** whether it is elevated and what will be missing (Security.evtx, LSASS command line, VSS/hives) and **continues anyway**.

Still on the USB, before you leave:

```bat
E:\tpv.exe info HOSTNAME-*.tpv
E:\tpv.exe verify HOSTNAME-*.tpv
```

Take the `.tpv` **and** the `.tpv.sha256` sidecar.

---

## Collect from a memory image

On the **analyst** machine, never the subject:

```bat
tpv memory memdump.raw -o memory.tpv
```

| Format | Recognition |
|---|---|
| Windows crash dump | `PAGEDU64` |
| LiME | `LiME` / little-endian magic |
| ELF core | `\x7fELF` |
| Raw / dd / winpmem `--format raw` | extension `.raw`, `.mem`, `.vmem`, `.dd`, `.bin`, `.img`, `.sav`, … |

The image is opened read-only. Kernel layout is recovered from the dump itself — no symbol download, no Volatility profile. Linux images (LiME, ELF cores) are analysed on this path too. Live `tpv collect` stays Windows-only.

Opening a dump in the viewer runs the same analysis and writes `memdump.raw.tpv` beside it.

---

## Open a case

```text
TreePView.exe
TreePView.exe E:\case.tpv
TreePView.exe D:\dumps\memdump.raw
```

Double-click, or **Open**. The backend sniffs SQLite/`TPV1` vs memory; a dump named `memory.img` still opens. Needs WebView2 (current Windows 10/11 already have it).

The viewer opens the case **read-only** except for regenerating the derived findings table. On read-only media, findings are skipped and the evidence still opens.

| Pane | What it is |
|---|---|
| Process tree | Parent/child forest. Select a node to pin the timeline. |
| Filter bar | Search, **IOC hunt** (one hash/IP/name per line, OR), source chips, **network**, **suspect time**, **≥severity**. |
| Timeline | Drag to zoom. One query with the tree and the search box. |
| Events / Logs / Lineage | Table, EVTX-focused Logs tab, or the forest as lineage. |
| Inspector | Case (findings, **manifest**, gaps, custody) or the selected event/entity. |

Title bar **CSV / JSONL / Report** exports the current filter (cap 20 000 rows) or a one-page markdown brief. Right-click copies `Label: value` for a ticket.

Local findings (7045, Run keys, encoded PowerShell, logon type 10, missing parent, unlinked EPROCESS) regenerate on open. Click a finding to jump to its evidence.

Dev UI (analysis PC only): `powershell -File bin\install.ps1 -Dev` → desktop window + http://127.0.0.1:5173/

---

## Integrity

| Layer | What it covers | How to check |
|---|---|---|
| Sidecar `case.tpv.sha256` | Bytes of the file on disk | Hash the file after transfer |
| Content digest inside the case | Row counts + artifact/blob hashes, sealed at finalize | `tpv verify`; viewer badge |
| Manifest | Per-source method, hash, errors | Inspector / `tpv info` |
| Collection profile | What was *requested* | Absence ≠ “did not happen” |

Ctrl+C → sealed case, custody warning `collection interrupted by operator`, **interrupted (sealed)** badge, verify OK. A hard kill before `finish` leaves `finalized=false` and no digest — different failure.

A `.tpv` is SQLite, `application_id = TPV1`. Regenerating findings does not change the content digest. Do not open the case with another SQLite tool in write mode.

---

## CLI

```text
tpv collect [--out PATH|DIR] [--allow-local-write] [--no-live] [--no-evtx] [--evtx-cap N] [--no-disk] [--pid N] [--max-ram MiB]
tpv memory IMAGE -o PATH
tpv info PATH [--json]
tpv tree PATH [--depth N]
tpv verify PATH
```

Exit `2` = refused to write on the examined volume. Exit `1` = verify mismatch or never-finalized case. Interrupted-but-sealed verifies OK.

---

## Not collected yet

Prefetch, scheduled tasks, and image hashes **are** collected unless `--no-disk`. Still not in this release:

| Artifact | Why |
|---|---|
| `$MFT` / `$UsnJrnl` / VSS | Needs elevation and a later `--full-disk` pass |
| Amcache, SRUM, ShimCache | Not in the shallow disk pass |
| Full registry hives | Live Run keys only |
| Live process memory / minidump | `tpv memory` on an already-acquired dump; no live `--memory` |
| Linux live collect | Viewer can parse Linux *images*; collect stays Windows |

Parser crate gate (developer): [gate-m0b.md](gate-m0b.md). Full artifact catalog: [artifacts.md](artifacts.md).
