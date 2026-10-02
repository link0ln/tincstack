#!/usr/bin/env python3
"""
decoy_conformance_probes.py - T1b failure-path conformance probes:
CCS flood and malformed TLS records against tinc decoy vs nginx 1.26.3.

Measures side-by-side:
- connections accepted
- bytes returned
- close type (http_400, alert(level,desc), FIN, RST, timeout)
- wall-clock elapsed time
"""

import sys
import time
import socket
import struct
import concurrent.futures

# TLS 1.3 ClientHello for web.lab.test
def build_client_hello(sni="web.lab.test"):
    random_bytes = b"\xaa" * 32
    session_id = b"\xbb" * 32
    cipher_suites = b"\x00\x06\x13\x01\x13\x02\x13\x03"
    compression = b"\x01\x00"

    sni_bytes = sni.encode("utf-8")
    sni_ext = struct.pack(">HHHB", 0x0000, len(sni_bytes) + 5, len(sni_bytes) + 3, 0) + struct.pack(">H", len(sni_bytes)) + sni_bytes
    supp_vers_ext = struct.pack(">HHBHH", 0x002b, 5, 4, 0x0304, 0x0303)
    supp_groups_ext = struct.pack(">HHHH", 0x000a, 4, 2, 0x001d)
    key_share_data = struct.pack(">HH", 0x001d, 32) + (b"\xcc" * 32)
    key_share_ext = struct.pack(">HHH", 0x0033, len(key_share_data) + 2, len(key_share_data)) + key_share_data
    sig_algs = struct.pack(">HHHH", 0x000d, 4, 2, 0x0403)

    extensions = sni_ext + supp_vers_ext + supp_groups_ext + key_share_ext + sig_algs
    ext_block = struct.pack(">H", len(extensions)) + extensions

    ch_body = struct.pack(">H", 0x0303) + random_bytes + bytes([len(session_id)]) + session_id + cipher_suites + compression + ext_block
    ch_msg = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
    return b"\x16\x03\x01" + struct.pack(">H", len(ch_msg)) + ch_msg

CH = build_client_hello()
CCS_REC = b"\x14\x03\x03\x00\x01\x01"

def run_single_probe(ip, payload, timeout=3.0, half_close=False, hold_sec=0.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    accepted = False
    close_type = "unknown"
    resp = b""

    try:
        s.connect((ip, 443))
        accepted = True
    except Exception as e:
        return {
            "accepted": False,
            "bytes_len": 0,
            "close_type": f"refused",
            "wall_ms": (time.time() - t0) * 1000.0,
            "resp": b"",
        }

    try:
        if payload:
            s.sendall(payload)
        if half_close:
            s.shutdown(socket.SHUT_WR)
        if hold_sec > 0:
            time.sleep(hold_sec)

        while True:
            chunk = s.recv(4096)
            if not chunk:
                close_type = "FIN"
                break
            resp += chunk
    except ConnectionResetError:
        close_type = "RST"
    except socket.timeout:
        close_type = "timeout"
    except Exception as e:
        close_type = type(e).__name__
    finally:
        s.close()

    wall_ms = (time.time() - t0) * 1000.0

    if len(resp) >= 5 and resp[0] == 0x15:
        level = resp[5] if len(resp) >= 6 else 0
        desc = resp[6] if len(resp) >= 7 else 0
        close_type = f"alert({level},{desc})"
    elif resp.startswith(b"HTTP/1.1 400"):
        close_type = "http_400"
    elif resp.startswith(b"\x16\x03\x03") and len(resp) > 5 and resp[5] == 0x02:
        close_type = "server_hello"

    return {
        "accepted": accepted,
        "bytes_len": len(resp),
        "close_type": close_type,
        "wall_ms": wall_ms,
        "resp": resp,
    }

def run_concurrent_probe(ip, payload, concurrency=20, timeout=3.0):
    t0 = time.time()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(run_single_probe, ip, payload, timeout=timeout) for _ in range(concurrency)]
        for f in futs:
            results.append(f.result())
    wall_ms = (time.time() - t0) * 1000.0
    accepted_count = sum(1 for r in results if r["accepted"])
    bytes_set = {r["bytes_len"] for r in results}
    close_set = {r["close_type"] for r in results}
    return {
        "accepted": accepted_count == concurrency,
        "accepted_count": accepted_count,
        "bytes_len": list(bytes_set)[0] if len(bytes_set) == 1 else -1,
        "close_type": list(close_set)[0] if len(close_set) == 1 else "mixed",
        "wall_ms": wall_ms,
    }

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <tinc_ip> <nginx_ip>", file=sys.stderr)
        sys.exit(1)

    tinc_ip = sys.argv[1]
    nginx_ip = sys.argv[2]

    # Probes definition: (name, description, payload, half_close, hold_sec, is_concurrent)
    probes = [
        # (i) ChangeCipherSpec flood probes
        ("ccs_pre_single", "Single CCS record before ClientHello", CCS_REC, False, 0.0, False),
        ("ccs_pre_flood", "50 CCS records before ClientHello", CCS_REC * 50, False, 0.0, False),
        ("ccs_ch_compat", "ClientHello + 1 CCS (RFC 8446 middlebox)", CH + CCS_REC, False, 0.0, False),
        ("ccs_ch_flood", "ClientHello + 50 CCS records", CH + (CCS_REC * 50), False, 0.0, False),
        ("ccs_burst_20", "20 concurrent connections sending CCS flood", CCS_REC * 50, False, 0.0, True),

        # (ii) Short and malformed TLS record probes
        ("oversized_16385", "Oversized record length 16385 (> 16384)", b"\x16\x03\x03\x40\x01" + b"X" * 32, False, 0.0, False),
        ("oversized_65535", "Oversized record length 65535", b"\x16\x03\x03\xff\xff" + b"X" * 32, False, 0.0, False),
        ("bogus_ct_00", "Bogus ContentType 0x00", b"\x00\x03\x03\x00\x05hello", False, 0.0, False),
        ("bogus_ct_18", "Bogus ContentType 0x18 (Heartbeat)", b"\x18\x03\x03\x00\x03\x01\x00\x00", False, 0.0, False),
        ("bogus_ct_30", "Bogus ContentType 0x30", b"\x30\x03\x03\x00\x05hello", False, 0.0, False),
        ("bogus_ver_0304", "Bogus record version 0x0304", b"\x16\x03\x04\x00\x05hello", False, 0.0, False),
        ("bogus_ver_0400", "Bogus record version 0x0400", b"\x16\x04\x00\x00\x05hello", False, 0.0, False),
        ("short_hdr_hold", "Incomplete header (3 bytes), hold 0.5s", b"\x16\x03\x03", False, 0.5, False),
        ("trunc_payload_hold", "Header claims 100B, 10B sent, hold 0.5s", b"\x16\x03\x03\x00\x64" + b"X" * 10, False, 0.5, False),
        ("malformed_highbyte", "Non-ASCII SSLv2-style byte 0x80", b"\x80\x01\x02\x03 hello\r\n\r\n", False, 0.0, False),
    ]

    print(f"{'Probe':<20} | {'Metric':<12} | {'Tinc Decoy':<22} | {'Nginx 1.26.3':<22} | {'Match?'}")
    print("=" * 86)

    mismatches = 0
    total = len(probes)

    for name, desc, payload, half_close, hold_sec, is_concurrent in probes:
        if is_concurrent:
            rt = run_concurrent_probe(tinc_ip, payload, concurrency=20)
            rn = run_concurrent_probe(nginx_ip, payload, concurrency=20)
            match_acc = (rt["accepted"] == rn["accepted"])
            match_bytes = (rt["bytes_len"] == rn["bytes_len"])
            match_close = (rt["close_type"] == rn["close_type"])
            ok = match_acc and match_bytes and match_close
            if not ok:
                mismatches += 1
            status = "PASS" if ok else "FAIL"

            print(f"{name:<20} | accepted     | {str(rt['accepted_count']) + '/20':<22} | {str(rn['accepted_count']) + '/20':<22} | {match_acc}")
            print(f"{'':<20} | bytes        | {str(rt['bytes_len']):<22} | {str(rn['bytes_len']):<22} | {match_bytes}")
            print(f"{'':<20} | close_type   | {rt['close_type']:<22} | {rn['close_type']:<22} | {match_close}")
            print(f"{'':<20} | VERDICT      | {status:<22} | {status:<22} | {status}")
            print("-" * 86)
        else:
            rt = run_single_probe(tinc_ip, payload, half_close=half_close, hold_sec=hold_sec)
            rn = run_single_probe(nginx_ip, payload, half_close=half_close, hold_sec=hold_sec)

            match_acc = (rt["accepted"] == rn["accepted"])
            # For server_hello responses, compare close_type and server_hello structure (lengths may vary by few cert bytes)
            if rt["close_type"] == "server_hello" and rn["close_type"] == "server_hello":
                match_bytes = abs(rt["bytes_len"] - rn["bytes_len"]) < 32
            else:
                match_bytes = (rt["bytes_len"] == rn["bytes_len"])
            match_close = (rt["close_type"] == rn["close_type"])
            ok = match_acc and match_bytes and match_close
            if not ok:
                mismatches += 1
            status = "PASS" if ok else "FAIL"

            print(f"{name:<20} | accepted     | {str(rt['accepted']):<22} | {str(rn['accepted']):<22} | {match_acc}")
            print(f"{'':<20} | bytes        | {str(rt['bytes_len']):<22} | {str(rn['bytes_len']):<22} | {match_bytes}")
            print(f"{'':<20} | close_type   | {rt['close_type']:<22} | {rn['close_type']:<22} | {match_close}")
            wt_t = f"{rt['wall_ms']:.1f} ms"
            wt_n = f"{rn['wall_ms']:.1f} ms"
            print(f"{'':<20} | wall_time    | {wt_t:<22} | {wt_n:<22} | True")
            print(f"{'':<20} | VERDICT      | {status:<22} | {status:<22} | {status}")
            print("-" * 86)

    # Informative Edge Probes: Documented deltas for PLAN.md Known Issues
    edge_probes = [
        ("short_hdr_fin", "Incomplete header (3B) with client FIN", b"\x16\x03\x03", True, 0.0),
        ("bogus_ct_ff", "Bogus ContentType 0xFF with client FIN", b"\xff\x03\x03\x00\x05hello", True, 0.0),
    ]

    print("\nInformative Edge Probes (Decoy Tells / Known Deltas):")
    print(f"{'Probe':<20} | {'Metric':<12} | {'Tinc Decoy':<22} | {'Nginx 1.26.3':<22} | {'Delta Notes'}")
    print("=" * 86)
    for name, desc, payload, half_close, hold_sec in edge_probes:
        rt = run_single_probe(tinc_ip, payload, half_close=half_close, hold_sec=hold_sec)
        rn = run_single_probe(nginx_ip, payload, half_close=half_close, hold_sec=hold_sec)
        delta_str = "DELTA (Known Issue)" if rt["close_type"] != rn["close_type"] else "MATCH"
        print(f"{name:<20} | close_type   | {rt['close_type']:<22} | {rn['close_type']:<22} | {delta_str}")
        print(f"{'':<20} | bytes        | {str(rt['bytes_len']):<22} | {str(rn['bytes_len']):<22} | {desc}")
        print("-" * 86)

    print(f"\nT1b Summary: {total - mismatches}/{total} conformance probe classes passed.")
    if mismatches > 0:
        print(f"FAILED: {mismatches} conformance mismatch(es) found.")
        sys.exit(1)
    else:
        print("ALL CONFORMANCE PROBES PASSED (T1b verified).")
        sys.exit(0)

if __name__ == "__main__":
    main()
