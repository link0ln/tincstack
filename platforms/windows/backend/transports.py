"""
transports.py — the transport / circumvention option surface of tinc.yaml
(docs/config-schema.md, "transport selection & negotiation"), Qt-free so the
GUI panel and the tests share one definition.

Two lists, deliberately separate (ARCHITECTURE.md §4, decision 2):

  * `Transports`          — ACCEPT list: what this listener answers.
                            Default: every carrier compiled in.
  * `PreferredTransports` — DIAL preference, in order; the first carrier
                            present in the peer's accept list is used.
                            Default: [plain]. "Tick QUIC" changes this list
                            on the ticking side only.

Everything here is an ordinary `options:` key; the daemon owns defaults, the
editor writes only what the user changed (see yaml_config.save).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

CARRIERS: tuple[str, ...] = ("plain", "obfs", "https", "quic")

CARRIER_HELP = {
    "plain": "Plain tinc UDP/TCP (default, unchanged wire image)",
    "obfs": "Obfuscated UDP: keyed junk around the handshake, header shaping",
    "https": "HTTPS-mimicking front: TLS session, probers see a decoy site",
    "quic": "QUIC carrier: SPTPS over datagrams + one stream, migration-friendly",
}


@dataclass(frozen=True)
class OptionSpec:
    name: str
    kind: str            # carriers | int | bool | port | front_port | path | str | magic
    default: Any
    help: str
    group: str
    minimum: int = 0
    maximum: int = 0


TRANSPORT_OPTIONS: tuple[OptionSpec, ...] = (
    OptionSpec("Transports", "carriers", list(CARRIERS),
               "Accept list: carriers this node's listener answers (default: all)", "negotiation"),
    OptionSpec("PreferredTransports", "carriers", ["plain"],
               "Dial preference, in order; first one in the peer's accept list wins (default: plain)",
               "negotiation"),
    OptionSpec("ObfsJunkPacketCount", "int", 0,
               "Junk datagrams sent around the handshake (0 = off)", "obfs", 0, 64),
    OptionSpec("ObfsJunkPacketMinSize", "int", 40, "Smallest junk datagram, bytes", "obfs", 1, 1400),
    OptionSpec("ObfsJunkPacketMaxSize", "int", 200, "Largest junk datagram, bytes", "obfs", 1, 1400),
    OptionSpec("ObfsInitHeaderJunkSize", "int", 0,
               "Junk bytes prepended to the handshake (0 = off)", "obfs", 0, 1024),
    OptionSpec("ObfsInitMagicHeader", "magic", 0,
               "Handshake magic header: 0 = off, N, or MIN-MAX range", "obfs"),
    # The core's key is HttpsPort (docs/config-schema.md). Until 2026-09-23 the
    # editor wrote `HttpsFront` / `HttpsFrontPort`, which no core reads: the
    # setting looked saved and did nothing.
    OptionSpec("HttpsPort", "front_port", 443,
               "TCP port of the HTTPS front; 0 = off (default 443 on a listening node)", "https"),
    OptionSpec("TlsCert", "path", "",
               "Real certificate chain (PEM). Empty = self-signed, generated at first start", "https"),
    OptionSpec("TlsKey", "path", "", "Private key for TlsCert (PEM); required with TlsCert", "https"),
    OptionSpec("HttpsDecoyRoot", "path", "",
               "Static content served to probers (empty = built-in default page)", "https"),
    OptionSpec("HttpsDecoyUpstream", "str", "",
               "Or transparently proxy probers to this host:port / URL", "https"),
    OptionSpec("QuicPort", "front_port", 443,
               "UDP port of the QUIC front; 0 = off (default 443 on a listening node)", "quic"),
)

SPEC_BY_NAME: dict[str, OptionSpec] = {o.name: o for o in TRANSPORT_OPTIONS}
GROUPS: tuple[str, ...] = ("negotiation", "obfs", "https", "quic")

_MAGIC_RE = re.compile(r"^(\d+)(?:-(\d+))?$")
_UPSTREAM_RE = re.compile(r"^(https?://\S+|[A-Za-z0-9.\-\[\]:]+:\d{1,5})$")


def parse_carrier_list(value: Any) -> list[str]:
    """Accept a YAML list or a 'a, b c' string; returns lowercase names as given
    (validation reports unknown ones)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = [str(x) for x in value]
    else:
        items = re.split(r"[,\s]+", str(value))
    return [s.strip().lower() for s in items if s.strip()]


def default_for(name: str) -> Any:
    spec = SPEC_BY_NAME[name]
    return list(spec.default) if isinstance(spec.default, list) else spec.default


def effective(options: dict) -> dict[str, Any]:
    """Every transport option with its effective value (file value or default)."""
    out: dict[str, Any] = {}
    for spec in TRANSPORT_OPTIONS:
        if spec.name in options:
            v = options[spec.name]
            out[spec.name] = parse_carrier_list(v) if spec.kind == "carriers" else v
        else:
            out[spec.name] = default_for(spec.name)
    return out


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _as_bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("yes", "true", "1", "on"):
        return True
    if s in ("no", "false", "0", "off"):
        return False
    return None


def validate(options: dict) -> list[str]:
    """Validate the transport keys present in `options`. Returns a list of
    human-readable errors (empty = valid). Absent keys are fine: every option
    has a working daemon default (ARCHITECTURE principle 5)."""
    errors: list[str] = []
    for spec in TRANSPORT_OPTIONS:
        if spec.name not in options:
            continue
        v = options[spec.name]
        if spec.kind == "carriers":
            lst = parse_carrier_list(v)
            if not lst:
                errors.append(f"{spec.name}: must list at least one carrier ({', '.join(CARRIERS)})")
            unknown = [c for c in lst if c not in CARRIERS]
            if unknown:
                errors.append(f"{spec.name}: unknown carrier(s) {', '.join(unknown)}; "
                              f"valid: {', '.join(CARRIERS)}")
            if len(set(lst)) != len(lst):
                errors.append(f"{spec.name}: duplicate carrier")
        elif spec.kind in ("int", "port", "front_port"):
            n = _as_int(v)
            lo, hi = {"port": (1, 65535), "front_port": (0, 65535)}.get(spec.kind, (spec.minimum, spec.maximum))
            if n is None:
                errors.append(f"{spec.name}: must be an integer, got {v!r}")
            elif not (lo <= n <= hi):
                errors.append(f"{spec.name}: must be between {lo} and {hi}, got {n}")
        elif spec.kind == "bool":
            if _as_bool(v) is None:
                errors.append(f"{spec.name}: must be yes/no, got {v!r}")
        elif spec.kind == "magic":
            m = _MAGIC_RE.match(str(v).strip())
            if not m:
                errors.append(f"{spec.name}: must be 0, N or MIN-MAX, got {v!r}")
            elif m.group(2) is not None and int(m.group(1)) >= int(m.group(2)):
                errors.append(f"{spec.name}: range MIN-MAX needs MIN < MAX, got {v!r}")
        elif spec.kind == "path":
            if v is not None and not isinstance(v, str):
                errors.append(f"{spec.name}: must be a path string")
        elif spec.kind == "str":
            if spec.name == "HttpsDecoyUpstream" and v and not _UPSTREAM_RE.match(str(v).strip()):
                errors.append(f"{spec.name}: expected host:port or http(s)://…, got {v!r}")
    lo = _as_int(options.get("ObfsJunkPacketMinSize", 40))
    hi = _as_int(options.get("ObfsJunkPacketMaxSize", 200))
    if lo is not None and hi is not None and lo > hi:
        errors.append("ObfsJunkPacketMinSize must be <= ObfsJunkPacketMaxSize")
    has_cert, has_key = bool(options.get("TlsCert")), bool(options.get("TlsKey"))
    if has_cert != has_key:
        errors.append("TlsCert and TlsKey must be set together (or both left empty for self-signed)")
    return errors


def changes(loaded: dict, edited: dict[str, Any]) -> dict[str, Any]:
    """Compute what the editor must write: {key: value} for keys whose edited
    value differs from what the file held, `None` meaning "remove the key".

    A key that was absent and whose edited value equals the daemon default is
    left absent — the file stays minimal and the daemon keeps owning the
    default. A key that was present and is edited back to the default is
    written explicitly (the user had pinned it on purpose)."""
    out: dict[str, Any] = {}
    for name, new in edited.items():
        spec = SPEC_BY_NAME.get(name)
        present = name in loaded
        old = loaded.get(name)
        if spec and spec.kind == "carriers":
            old_n = parse_carrier_list(old) if present else None
            new_n = parse_carrier_list(new)
        else:
            old_n, new_n = old, new
        if present:
            if old_n != new_n:
                out[name] = new_n
        else:
            if spec is not None and new_n == default_for(name):
                continue
            if spec is not None and spec.kind in ("path", "str") and new_n in ("", None):
                continue
            out[name] = new_n
    return out


def apply_changes(options: dict, delta: dict[str, Any]) -> None:
    """Apply a `changes()` result to an options dict in place."""
    for k, v in delta.items():
        if v is None:
            options.pop(k, None)
        else:
            options[k] = v
