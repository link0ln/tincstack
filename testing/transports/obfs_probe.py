#!/usr/bin/env python3
# obfs_probe.py -- a stand-in for a malicious mesh member (security review R,
# proof for finding M5-2). It knows both endpoints' Ed25519 *public* keys (every
# member does), derives the obfs v2 *bootstrap* key exactly as core/tincd/src/
# obfs.c does, and tries to unseal captured obfs datagrams with it.
#
# The point: bootstrap frames (the first few, cold-start) unseal -- proving the
# derivation is correct and that a third party CAN read those. Steady-state
# frames use the per-link SESSION key (seeds exchanged inside SPTPS, which the
# probe never sees), so they DO NOT unseal. That is the fix for M5-2.
#
# stdlib only (hashlib for SHA-512; ChaCha20 + Poly1305 reimplemented to match
# tinc's non-standard seqnr-as-IV construction). Nothing installed on the host.
#
# Usage:
#   obfs_probe.py decrypt <pcap> <pubkeyA_b64> <pubkeyB_b64>
#       -> prints "decryptable=<n> total=<m>"
#   obfs_probe.py dump <pcap> <dst_ip> <count>
#       -> prints hex of the first <count> UDP payloads destined to <dst_ip>
import sys
import hashlib
import struct

# ---- tinc ChaCha20 (DJB variant, 64-bit nonce + 64-bit counter) ------------
SIGMA = b"expand 32-byte k"


def _rotl(v, c):
    return ((v << c) | (v >> (32 - c))) & 0xffffffff


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = _rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = _rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = _rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = _rotl(x[b] ^ x[c], 7)


def chacha20_block(key32, counter, nonce8):
    # state layout matches chacha.c: const|key|counter(2)|nonce(2), all LE words.
    st = list(struct.unpack("<4I", SIGMA))
    st += list(struct.unpack("<8I", key32))
    st += [counter & 0xffffffff, (counter >> 32) & 0xffffffff]
    st += list(struct.unpack("<2I", nonce8))
    x = list(st)
    for _ in range(10):  # 20 rounds = 10 double rounds
        _qr(x, 0, 4, 8, 12)
        _qr(x, 1, 5, 9, 13)
        _qr(x, 2, 6, 10, 14)
        _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15)
        _qr(x, 1, 6, 11, 12)
        _qr(x, 2, 7, 8, 13)
        _qr(x, 3, 4, 9, 14)
    out = bytes()
    for i in range(16):
        out += struct.pack("<I", (x[i] + st[i]) & 0xffffffff)
    return out


# ---- Poly1305 (RFC 7539 arithmetic) ----------------------------------------
def poly1305_mac(msg, key32):
    r = int.from_bytes(key32[0:16], "little")
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key32[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        acc = ((acc + n) * r) % p
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def tinc_open(key64, seqnr, sealed):
    # sealed = ciphertext (inner_len bytes) || 16-byte Poly1305 tag.
    # Mirror chacha_poly1305_decrypt: IV = seqnr big-endian (put_u64), poly key
    # = ChaCha block at counter 0, tag over the ciphertext (no AAD).
    if len(sealed) < 16:
        return None
    ct, tag = sealed[:-16], sealed[-16:]
    nonce8 = seqnr.to_bytes(8, "big")
    key32 = key64[:32]
    poly_key = chacha20_block(key32, 0, nonce8)[:32]
    if poly1305_mac(ct, poly_key) != tag:
        return None
    # (plaintext not needed for the probe; a matching tag means "unsealed")
    return ct


# ---- obfs v2 key derivation (matches obfs.c) -------------------------------
def _sha512(*parts):
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def derive_base(pa, pb):
    lo, hi = sorted([pa, pb])  # strcmp order on the base64 strings
    return _sha512(b"tincstack-obfs-v2\x00", lo.encode(), b"|", hi.encode())


def kdf(ctx, label, secret):
    return _sha512(ctx + b"\x00", label + b"\x00", secret)


def boot_keys(pa, pb):
    base = derive_base(pa, pb)
    keys = []
    for dirlabel in (b"l2h", b"h2l"):
        k = kdf(b"tincstack-obfs-key", dirlabel, base)
        mask = kdf(b"tincstack-obfs-iv", dirlabel, base)[:8]
        keys.append((k, mask))
    return keys


def try_unseal(payload, keys):
    # try both directions and both magic-prefix lengths (0 and 4)
    for mlen in (0, 4):
        if len(payload) < mlen + 10 + 16:
            continue
        for (k, mask) in keys:
            nb = payload[mlen:mlen + 8]
            counter = 0
            for i in range(8):
                counter = (counter << 8) | (nb[i] ^ mask[i])
            clen = (payload[mlen + 8] << 8) | payload[mlen + 9]
            if clen < 16 or mlen + 10 + clen > len(payload):
                continue
            sealed = payload[mlen + 10:mlen + 10 + clen]
            if tinc_open(k, counter, sealed) is not None:
                return True
    return False


# ---- pcap parsing (DLT_EN10MB) ---------------------------------------------
def pcap_payloads(path, dst_ip=None):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        return
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        if len(pkt) < 14:
            continue
        l2 = 14 if linktype == 1 else 0  # Ethernet
        ip = pkt[l2:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0f) * 4
        if ip[9] != 17:  # UDP
            continue
        dip = ".".join(str(b) for b in ip[16:20])
        if dst_ip and dip != dst_ip:
            continue
        udp = ip[ihl:]
        if len(udp) < 8:
            continue
        ulen = struct.unpack(">H", udp[4:6])[0]
        payload = udp[8:ulen] if ulen >= 8 else udp[8:]
        if payload:
            yield payload


def tinc_seal(key64, seqnr, plaintext):
    # Mirror chacha_poly1305_encrypt: IV = seqnr big-endian, poly key = ChaCha
    # block at counter 0, ciphertext = plaintext XOR keystream from block 1,
    # tag = Poly1305 over the ciphertext (no AAD). Produces exactly what
    # tinc_open()/try_unseal() accept, so a seal->unseal round-trip is a
    # self-contained positive control for the probe's key derivation.
    nonce8 = seqnr.to_bytes(8, "big")
    key32 = key64[:32]
    poly_key = chacha20_block(key32, 0, nonce8)[:32]
    ks = b""
    counter = 1
    while len(ks) < len(plaintext):
        ks += chacha20_block(key32, counter, nonce8)
        counter += 1
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = poly1305_mac(ct, poly_key)
    return ct + tag


def selftest(pa, pb):
    # Prove the probe can derive the public-key bootstrap key and unseal a frame
    # sealed under it -- independent of any capture. If this passes but the
    # steady capture yields decryptable=0, the steady traffic is genuinely on a
    # different (per-link session) key, not merely unparsed by a broken probe.
    keys = boot_keys(pa, pb)
    ok = True
    for mlen in (0, 4):
        for (k, mask) in keys:
            counter = 0x0123456789ab
            sealed = tinc_seal(k, counter, b"obfs positive control " * 3)
            nb = bytes((counter >> (8 * (7 - i))) & 0xff ^ mask[i] for i in range(8))
            clen = len(sealed)
            frame = (b"\x00" * mlen) + nb + bytes([clen >> 8, clen & 0xff]) + sealed
            if not try_unseal(frame, keys):
                ok = False
    print("selftest=%s" % ("ok" if ok else "fail"))
    return ok


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: decrypt|dump|selftest ...")
    cmd = sys.argv[1]
    if cmd == "selftest":
        selftest(sys.argv[2], sys.argv[3])
    elif cmd == "decrypt":
        pcap, pa, pb = sys.argv[2], sys.argv[3], sys.argv[4]
        keys = boot_keys(pa, pb)
        total = dec = 0
        for p in pcap_payloads(pcap):
            total += 1
            if try_unseal(p, keys):
                dec += 1
        print("decryptable=%d total=%d" % (dec, total))
    elif cmd == "dump":
        pcap, dst, cnt = sys.argv[2], sys.argv[3], int(sys.argv[4])
        n = 0
        for p in pcap_payloads(pcap, dst):
            if len(p) < 26:
                continue
            print(p.hex())
            n += 1
            if n >= cnt:
                break
    else:
        sys.exit("unknown cmd")


if __name__ == "__main__":
    main()
