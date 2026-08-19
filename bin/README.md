# `bin/` — what you run

GitHub Releases ship `tpv.exe` and `TreePView.exe`. This folder is also where `install.ps1` writes a local build. Do not copy the rest of the repository onto an examined host.

| File | Role |
|---|---|
| `tpv.exe` | Collector. USB kit. No installer, no network. |
| `TreePView.exe` | Viewer. Analysis machine only. |
| `install.ps1` | Builds both on a development PC. `-Dev` starts live reload. |
| `HOW-TO.txt` | Field card to keep on the USB. |

The `.exe` files are **not** in git. Get them from [Releases](https://github.com/newtonjin/TreePView/releases) or rebuild:

```powershell
powershell -File bin\install.ps1
```

## Collect

Copy **`tpv.exe`** (and `HOW-TO.txt`) onto USB. Leave `TreePView.exe` on the analysis PC.

```text
E:\tpv.exe collect --out E:\
E:\tpv.exe verify HOSTNAME-*.tpv
```

`--out` omitted or a directory gets `HOSTNAME-YYYYMMDDTHHMMSSZ.tpv`. Ctrl+C seals a partial case. `--allow-local-write` contaminates the examined volume and is recorded in custody.

## Open

```text
TreePView.exe
TreePView.exe E:\case.tpv
```

Operator guide: [docs/usage.md](../docs/usage.md).
