#!/usr/bin/env python3
"""Write the seed corpora under corpus/<harness>/ (stdlib only, run from anywhere).

Seeds are shaped like the real inputs so the fuzzers start deep in the
parsers. None of them contains key material: the PEM blocks are dummies.
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


def put(harness, name, data):
    d = os.path.join(HERE, "corpus", harness)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


YAML = """\
networks:
  tincstack:
    options:
      Name: nodea
      Mode: router
      Port: 655
      AddressPool: 10.138.0.0/24
      ConnectTo: [nodeb, nodec]
      UDPRebindOnWake: yes
      Empty: ""
    keys:
      ed25519_priv: |
        -----BEGIN ED25519 PRIVATE KEY-----
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        -----END ED25519 PRIVATE KEY-----
    scripts:
      tinc-up: |
        #!/bin/sh
        ip link set $INTERFACE up
    hosts:
      nodea: |
        Subnet = 10.138.0.1/32
        Transports = plain, sf
        Ed25519PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      nodeb: "Address = 1.2.3.4\\nPort = 655\\n"
      nodec: 'Address = 5.6.7.8'
"""
put("fuzz_yamlconf", "daemon.yaml", YAML)
put("fuzz_yamlconf", "empty.yaml", "# only a comment\n\n")
put("fuzz_yamlconf", "seq.yaml", "a:\n  - x\n  - \"y\\n\"\n  -\n    k: v\nb: {}\nc: []\n")

PAYLOAD = """\
Name = peer
NetName = tincstack
ConnectTo = nodea
Mode = router
AddressPool = 10.138.0.0/24
Subnet = 10.138.0.2/32
Ifconfig = 10.138.0.2/24
Route = 10.140.0.0/24 10.138.0.1
ScriptsInterpreter = /bin/evil
HttpsDecoyRoot = /etc
ObfsJunkPacketCount = 3
#---------------------------------------------------------------#
Name = nodea
Subnet = 10.138.0.1/32
Ed25519PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----BEGIN RSA PUBLIC KEY-----
QUJD
-----END RSA PUBLIC KEY-----
Address = 10.16.10.2
Port = 655
"""
put("fuzz_invitation", "payload", b"\x02" + PAYLOAD.encode())
put("fuzz_invitation", "payload-force", b"\x03" + PAYLOAD.encode())
put("fuzz_invitation", "url", b"\x00" + b"10.16.10.2:655/" + b"A" * 48)
put("fuzz_invitation", "url6", b"\x00" + b"[2001:db8::1]:655/" + b"B" * 48)
# Regression: a control character in the payload used to abort() the joiner.
put("fuzz_invitation", "regress-ctrl-abort", b"\x02Name = peer\n\x01Mode = router\n")
# Regression: a 300-byte inviter-chosen Name passed check_id() and produced a
# YAML key the parser refuses -- the joiner wrote a config that did not load.
put("fuzz_invitation", "regress-long-name", b"\x02Name = pe" + b"T" * 300 + b"er3\n--o0.2\nPo =r 65t5\n")

put("fuzz_classify", "tinc-id", b"0 nodea 17.7\n")
put("fuzz_classify", "tls", bytes([0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01]))
put("fuzz_classify", "http", b"GET / HTTP/1.1\r\n")
put("fuzz_classify", "h2", b"PRI * HTTP/2.0\r\n")
put("fuzz_classify", "list", b"plain, sf,quic obfs")
put("fuzz_classify", "quic", bytes([0xc3, 0, 0, 0, 1]) + b"\x00" * 40)
SF_MAGIC = bytes([0x9f, 0x74, 0x73, 0x66, 0x6c, 0x77])


def sf_frame(typ, flags, cid, seq, ack, payload=b""):
    return SF_MAGIC + bytes([typ, flags]) + cid + struct.pack("!II", seq, ack) + payload


put("fuzz_classify", "sf", sf_frame(1, 1, b"\x01" * 8, 0, 0, b"0 nodea 17.7\n"))


def rec(flags, frame):
    return bytes([flags]) + struct.pack("!H", len(frame)) + frame


cid = b"\x11\x22\x33\x44\x55\x66\x77\x88"
syn = sf_frame(1, 1, cid, 0, 0, b"0 nodeb 17.7\n")
data2 = sf_frame(1, 0, cid, 13, 13, b"1 hello world\n")
ack = sf_frame(2, 0, cid, 0, 27)
close = sf_frame(3, 0, cid, 27, 27)
reset = sf_frame(4, 0, cid, 0, 0)
put("fuzz_sf", "handshake", rec(0, syn) + rec(0, data2) + rec(0, ack) + rec(2, close))
put("fuzz_sf", "hijack", rec(0, syn) + rec(1, data2) + rec(1, reset) + rec(0, reset))
put("fuzz_sf", "unknown-cid", rec(0, ack) + rec(2, ack) + rec(0, data2))
put("fuzz_sf", "bad-meta", rec(0, sf_frame(1, 1, cid, 0, 0, b"\xff\xff\xff")))

put("fuzz_pool", "pending", "10.99.0.0/24\nName = x\nSubnet = 10.99.0.2/32\nSubnet = 10.99.0.3/32\n")
put("fuzz_pool", "wide", "10.99.0.0/24\nName = exit\nSubnet = 0.0.0.0/0\nSubnet = 10.99.0.0/16\n")
put("fuzz_pool", "bad", "10.99.0.0/33\nSubnet = garbage\n")
print("seeds written under", os.path.join(HERE, "corpus"))
