"""transports: validation and the write-only-what-changed rule."""
import transports as tr


def test_defaults_match_schema():
    eff = tr.effective({})
    assert eff["Transports"] == ["plain", "obfs", "https", "quic"]
    assert eff["PreferredTransports"] == ["plain"]
    assert eff["HttpsPort"] == 443 and "HttpsFront" not in eff
    assert eff["QuicPort"] == 443 and eff["ObfsJunkPacketCount"] == 0
    assert eff["ObfsPort"] == 0


def test_validate_ok_for_absent_and_sane():
    assert tr.validate({}) == []
    assert tr.validate({"Transports": ["quic", "plain"], "PreferredTransports": "quic, plain",
                        "ObfsJunkPacketCount": 3, "ObfsInitMagicHeader": "1000-2000",
                        "HttpsPort": 8443,
                        "TlsCert": "/c.pem", "TlsKey": "/k.pem",
                        "HttpsDecoyUpstream": "example.org:443", "QuicPort": 443}) == []


def test_validate_errors():
    errs = tr.validate({"Transports": [], "PreferredTransports": ["tcp", "plain", "plain"],
                        "ObfsJunkPacketCount": "x", "ObfsJunkPacketMinSize": 500,
                        "ObfsJunkPacketMaxSize": 100, "ObfsInitMagicHeader": "9-5",
                        "HttpsPort": 70000,
                        "TlsCert": "/c.pem", "HttpsDecoyUpstream": "not a host", "QuicPort": -1})
    joined = "\n".join(errs)
    for needle in ("Transports: must list at least one", "unknown carrier(s) tcp", "duplicate carrier",
                   "ObfsJunkPacketCount: must be an integer", "MinSize must be <=",
                   "ObfsInitMagicHeader: range",
                   "HttpsPort: must be between 0 and 65535", "TlsCert and TlsKey",
                   "HttpsDecoyUpstream: expected", "QuicPort: must be between"):
        assert needle in joined, needle


def test_changes_writes_only_user_edits():
    loaded = {"Name": "a", "Transports": ["plain", "quic"]}
    edited = {"Transports": ["plain", "quic"],          # unchanged -> nothing
              "PreferredTransports": ["quic", "plain"],  # absent, non-default -> write
              "HttpsPort": 443,                          # absent, default -> stay absent
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
    tr.apply_changes(opts, {"QuicPort": None, "HttpsPort": 0})
    assert opts == {"Name": "a", "HttpsPort": 0}


def test_front_ports_zero_is_off_not_an_error():
    # The core reads 0 as "no front" (transport_front_port); the editor must let it through.
    assert tr.validate({"HttpsPort": 0, "QuicPort": 0, "ObfsPort": 0}) == []
    assert tr.changes({}, {"HttpsPort": 0}) == {"HttpsPort": 0}


def test_host_preferred_transport_read_and_write():
    host_blob = "Address = 203.0.113.9\nSubnet = 10.99.0.2/32\nEd25519PublicKey = BBBB\n"
    assert tr.host_preferred_transport(host_blob) == ""
    updated = tr.set_host_preferred_transport(host_blob, "quic")
    assert tr.host_preferred_transport(updated) == "quic"
    assert "PreferredTransports = quic" in updated
    assert "Ed25519PublicKey = BBBB" in updated
    # Replacing existing preference updates in place without duplicating lines
    updated2 = tr.set_host_preferred_transport(updated, "https")
    assert tr.host_preferred_transport(updated2) == "https"
    assert updated2.count("PreferredTransports") == 1
    # Single-flow UDP (sf) and Single-flow TCP (sftcp)
    for sf_mode in ("sf", "sftcp"):
        u_sf = tr.set_host_preferred_transport(updated2, sf_mode)
        assert tr.host_preferred_transport(u_sf) == sf_mode
    assert tr.validate({"PreferredTransports": ["sf", "sftcp", "plain"]}) == []
    # Setting to "" / auto removes the line cleanly
    cleared = tr.set_host_preferred_transport(updated2, "")
    assert tr.host_preferred_transport(cleared) == ""
    assert "PreferredTransports" not in cleared

