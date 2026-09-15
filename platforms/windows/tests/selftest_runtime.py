"""Manual Windows end-to-end check of the runtime against the real core:
empty network -> tincd materialises keys (M1) -> Wintun adapter appears ->
graceful stop -> adapter removed. Uses a throwaway 'lab' network with no peers
so it cannot collide with a real one. NEEDS ADMIN (Wintun) and the cross-built
binaries in resources/. Not collected by pytest (no test_ prefix); run with
    python tests\\selftest_runtime.py
Last result before adoption (original tinc-manager, 2026-06-18): adapter
'lab [Up] tinc Tunnel', IP 10.123.0.1/24, stop -> adapter count 0.
Not re-run since the tincstack adoption: no Windows host in the build lab."""
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "backend"))
import paths  # noqa: E402
import runtime as rt_mod  # noqa: E402
import yaml_config as yc  # noqa: E402


def ps(cmd: str) -> str:
    p = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                       capture_output=True, text=True)
    return (p.stdout or "").strip()


def main() -> int:
    if sys.platform != "win32":
        print("SKIP: Windows-only (Wintun)")
        return 0
    ok, msg = paths.binaries_present()
    print(msg)
    if not ok:
        return 2
    tmp = tempfile.mkdtemp(prefix="tincmgr_rt_")
    app = yc.AppConfig(path=os.path.join(tmp, "tinc.yaml"))
    app.networks["lab"] = yc.NetworkCfg(
        name="lab", autostart=True,
        options={"Name": "labbox", "Mode": "router",
                 "DeviceType": "wintun", "WintunAddress": "10.123.0.1/24"})
    yc.save(app)
    rt = rt_mod.Runtime(app)
    print("tincd:", rt.tincd, "exists:", os.path.isfile(rt.tincd))
    print("runtime base:", rt.base)

    # this is exactly what GUI autostart does; the core generates the keys itself
    results = rt.start_autostart()
    print("autostart:", results)
    time.sleep(2.5)
    print("is_running:", rt.is_running("lab"))
    keys = yc.load(app.path).net("lab").keys
    print("keys materialised by the daemon:", sorted(keys))
    print("adapter:", ps("(Get-NetAdapter -IncludeHidden -EA SilentlyContinue | "
                         "Where-Object {$_.Name -eq 'lab'} | Select-Object -First 1 | "
                         "ForEach-Object {$_.Name + ' [' + $_.Status + '] ' + $_.InterfaceDescription})"))
    print("adapter_ip:", ps("(Get-NetIPAddress -InterfaceAlias 'lab' -AddressFamily IPv4 "
                            "-EA SilentlyContinue | ForEach-Object {$_.IPAddress + '/' + $_.PrefixLength}) -join ','"))

    ok, msg = rt.stop("lab")
    print("stop:", ok, msg)
    time.sleep(1.5)
    print("is_running_after_stop:", rt.is_running("lab"))
    print("adapter_after_stop_count:",
          ps("@(Get-NetAdapter -IncludeHidden -EA SilentlyContinue | "
             "Where-Object {$_.Name -eq 'lab'}).Count"))
    print("DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
