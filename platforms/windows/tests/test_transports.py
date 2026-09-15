"""transports: validation and the write-only-what-changed rule."""
import transports as tr


def test_defaults_match_schema():
    eff = tr.effective({})
    assert eff["Transports"] == ["plain", "obfs", "https", "quic"]
    assert eff["PreferredTransports"] == ["plain"]
    assert eff["HttpsFront"] is False and eff["HttpsFrontPort"] == 443
    assert eff["QuicPort"] == 443 and eff["ObfsJunkPacketCount"] == 0


def test_validate_ok_for_absent_and_sane():
    assert tr.validate({}) == []
    assert tr.validate({"Transports": ["quic", "plain"], "PreferredTransports": "quic, plain",
                        "ObfsJunkPacketCount": 3, "ObfsInitMagicHeader": "1000-2000",
                        "HttpsFront": "yes", "HttpsFrontPort": 8443,
                        "TlsCert": "/c.pem", "TlsKey": "/k.pem",
                        "HttpsDecoyUpstream": "example.org:443", "QuicPort": 443}) == []


def test_validate_errors():
    errs = tr.validate({"Transports": [], "PreferredTransports": ["tcp", "plain", "plain"],
                        "ObfsJunkPacketCount": "x", "ObfsJunkPacketMinSize": 500,
                        "ObfsJunkPacketMaxSize": 100, "ObfsInitMagicHeader": "9-5",
                        "HttpsFront": "maybe", "HttpsFrontPort": 70000,
                        "TlsCert": "/c.pem", "HttpsDecoyUpstream": "not a host", "QuicPort": 0})
    joined = "\n".join(errs)
    for needle in ("Transports: must list at least one", "unknown carrier(s) tcp", "duplicate carrier",
                   "ObfsJunkPacketCount: must be an integer", "MinSize must be <=",
                   "ObfsInitMagicHeader: range", "HttpsFront: must be yes/no",
                   "HttpsFrontPort: must be between 1 and 65535", "TlsCert and TlsKey",
                   "HttpsDecoyUpstream: expected", "QuicPort: must be between"):
        assert needle in joined, needle


def test_changes_writes_only_user_edits():
    loaded = {"Name": "a", "Transports": ["plain", "quic"]}
    edited = {"Transports": ["plain", "quic"],          # unchanged -> nothing
              "PreferredTransports": ["quic", "plain"],  # absent, non-default -> write
              "HttpsFront": False,                       # absent, default -> stay absent
              "QuicPort": 443,                           # absent, default -> stay absent
              "TlsCert": "",                             # absent, empty -> stay absent
              "ObfsJunkPacketCount": 4}                  # absent, non-default -> write
    assert tr.changes(loaded, edited) == {"PreferredTransports": ["quic", "plain"],
                                          "ObfsJunkPacketCount": 4}


def test_changes_present_key_back_to_default_is_explicit():
    loaded = {"PreferredTransports": ["quic", "plain"]}
    assert tr.changes(loaded, {"PreferredTransports": ["plain"]}) == {"PreferredTransports": ["plain"]}
    # string form in the file, list in the editor: compared semantically
    assert tr.changes({"Transports": "plain, quic"}, {"Transports": ["plain", "quic"]}) == {}


def test_apply_changes_removes_on_none():
    opts = {"Name": "a", "QuicPort": 4433}
    tr.apply_changes(opts, {"QuicPort": None, "HttpsFront": True})
    assert opts == {"Name": "a", "HttpsFront": True}
