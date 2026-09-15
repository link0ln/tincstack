# tincmgr — the tincstack Windows client

One `.exe` + one `.yaml`. Drop them in a folder, run, and the VPN networks
defined in the config come up — no install, no services, no hand-editing
`tinc.conf`/`hosts`. Adopted from the `tinc-manager` prototype (PySide6) and
repointed at the tincstack core (`core/tincd`, cross-built with mingw-w64).

The executable bundles the core (`tincd.exe`, `tinc.exe`) and `wintun.dll`,
plus the management GUI. Networks run as child processes of the app; **Wintun**
tunnel adapters are created on connect and removed on disconnect, with IPs
assigned automatically.

## Use it

1. Put `tincmgr.exe` and (optionally) a `tinc.yaml` in the same folder.
2. Run `tincmgr.exe` (it elevates via UAC — needed to create tunnel adapters).
3. No config? **＋** adds an empty network; **Start** lets the daemon
   materialise its name, port, address pool and keys (zero-config, principle 2).
   **✉ Invite…** hands out a one-line invitation; on another machine
   **⤵ Join…** pastes it and the network appears in that machine's `tinc.yaml`.

That's it — two files. Runtime side-files (`<net>/`, `<net>-tincd.log`) are
written next to the YAML.

## The config — one YAML for everything

`tinc.yaml` follows [`docs/config-schema.md`](../../docs/config-schema.md); the
daemon owns the file and writes it too (learned peer keys, materialised
defaults). The GUI therefore:

* saves **atomically** (temp file + fsync + rename — the file with your only
  private keys is never truncated in place);
* **re-reads before merging** and writes only the keys you changed, so a peer
  the daemon learned while you were editing is not lost;
* refuses to overwrite a file it cannot parse, and opens with an error banner
  (not a crash) when `tinc.yaml` is malformed — fix it in *Raw YAML…*.

See `tinc.example.yaml` for an annotated example.

## GUI

* **Peers & Traffic** — live peer table (direct-UDP / relay / down, via-node,
  RTT, PMTU, rx/tx, subnets) + per-network throughput graph. Sampling runs on
  a worker thread; the window never blocks on `tinc.exe`.
* **Network** — tinc.conf options (with a catalog of known options), nodes/hosts
  add/edit/delete/import/export, private keys generate/import, autostart.
* **Transports** — `Transports` (accept list, default all) and
  `PreferredTransports` (dial preference — tick *quic* and move it up to prefer
  QUIC; the peer follows because its accept list already includes it),
  obfuscated-UDP parameters, the HTTPS front (`HttpsFront*`, `TlsCert`/`TlsKey`,
  decoy root/upstream) and `QuicPort`. Validated before saving; only changed
  keys are written.
* Toolbar: Start / Stop / Restart, **Invite…**, **Join…**, run-at-Windows-startup
  (elevated Scheduled Task), open folder, reload.

Daemon logs (`<net>-tincd.log`) rotate by size (2 MB, two backups) **while the
daemon runs**.

## Build

See [`build-windows.md`](build-windows.md): the core cross-builds on Linux in
Docker (`build-core-win.sh`); the onefile `tincmgr.exe` builds on a Windows host
with PyInstaller (`tincmgr.spec`).

## Headless CLI (Linux servers, containers, tests)

`cli.py` drives the same backend without Qt against a Linux core build
(`tincd`/`tinc` from `$TINCSTACK_BIN_DIR` or `$PATH`):

```
python3 cli.py -c tinc.yaml up mynet          # empty YAML is fine
python3 cli.py -c tinc.yaml invite mynet laptop
python3 cli.py -c tinc.yaml join -n mynet <invitation>
python3 cli.py -c tinc.yaml peers mynet
```

## Tests

```
docker run --rm -v "$PWD:/w" -w /w <image with PySide6 pyqtgraph pyyaml pytest> \
    env QT_QPA_PLATFORM=offscreen python -m pytest -q tests
```

`tests/` cover the YAML model (atomic save, concurrent-writer merge, malformed
guard), the transports schema, the `tinc` wrapper (mocked runner), the runtime
(log rotation, start/stop with fake binaries) and the GUI offscreen (invite/
join dialogs, transports tab, threading). `tests/selftest_runtime.py` is the
manual Windows end-to-end check (real core, Wintun, admin).

## Layout

```
main.py                  GUI entry point (PySide6)
cli.py                   headless CLI, same backend
backend/
  paths.py               core binary + config discovery (frozen / resources / env / PATH)
  yaml_config.py         the single YAML: model, atomic merge-save, diff/patch
  transports.py          transport option schema, validation, change set
  runtime.py             spawn/stop tincd, rotating log sink, keygen
  tinc_control.py        `tinc dump` parsers, invite/join (mockable runner)
  management.py          elevation, Scheduled-Task autostart, firewall rule
  netmtu.py              Wintun MTU clamp via IP Helper API
gui/
  workers.py             QThread pool: every subprocess off the Qt thread
  dialogs.py             Invite / Join / raw YAML dialogs
  transports_panel.py    the Transports editor widgets
resources/               tincd.exe, tinc.exe, wintun.dll (gitignored; from the cross-build)
tincmgr.spec             PyInstaller onefile spec
build-core-win.sh        core cross-build → resources/
build-windows.md         the exact build commands
tools/import_from_disk.py   migrate a classic tinc tree into one tinc.yaml
tests/                   pytest suite + manual Windows selftest
```
