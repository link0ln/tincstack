#!/usr/bin/env python3
"""
replay_probe.py - Active probe / replay wire test tool (T1d(b)).

Features:
1. Replay first record / datagram from a new source at +T1 and +T2 (+5s, +40s).
2. Send same-size random garbage to the ports.
3. Compare reactions against reference nginx (HTTPS / HTTP/3) and verify
   closed-port behavior for obfs.

Standard library only.
"""

import argparse
import os
import socket
import sys
import time

def send_tcp(ip, port, data, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    resp = b""
    close_type = "unknown"
    try:
        s.connect((ip, port))
        s.sendall(data)
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
        "len": len(resp),
        "close_type": close_type,
        "wall_ms": wall_ms,
        "resp_hex": resp[:32].hex()
    }

def send_udp(ip, port, data, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    resp = b""
    close_type = "unknown"
    try:
        s.sendto(data, (ip, port))
        resp, _ = s.recvfrom(65535)
        close_type = "reply"
    except socket.timeout:
        close_type = "silence"
    except ConnectionResetError:
        close_type = "icmp_unreach"
    except Exception as e:
        close_type = type(e).__name__
    finally:
        s.close()

    wall_ms = (time.time() - t0) * 1000.0

    desc = close_type
    if resp:
        if resp[0] & 0x80:
            desc = "long_header"
        else:
            desc = "short_header"

    return {
        "len": len(resp),
        "close_type": desc,
        "wall_ms": wall_ms,
        "resp_hex": resp[:32].hex()
    }

def main():
    parser = argparse.ArgumentParser(description="Active probe / replay wire test (T1d)")
    parser.add_argument("--proto", choices=["https", "quic", "obfs"], required=True)
    parser.add_argument("--tinc-ip", required=True)
    parser.add_argument("--nginx-ip", default="")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--payload-hex", default="")
    parser.add_argument("--wait-short", type=float, default=5.0)
    parser.add_argument("--wait-long", type=float, default=40.0)
    parser.add_argument("--mode", choices=["replay", "garbage"], required=True)

    args = parser.parse_args()

    if args.payload_hex:
        payload = bytes.fromhex(args.payload_hex.strip())
    else:
        # Fallback default sizes if payload not supplied
        payload = b"\x16\x03\x01\x02\x00" + os.urandom(507) if args.proto == "https" else os.urandom(1200)

    if args.mode == "garbage":
        garbage = os.urandom(len(payload))
        if args.proto == "https":
            rt = send_tcp(args.tinc_ip, args.port, garbage)
            rn = send_tcp(args.nginx_ip, args.port, garbage)
            match = (rt["len"] == rn["len"]) and (rt["close_type"] == rn["close_type"])
            print(f"GARBAGE https ({len(garbage)} B): tinc={rt['close_type']}({rt['len']}B) nginx={rn['close_type']}({rn['len']}B) -> match={match}")
            sys.exit(0 if match else 1)
        elif args.proto == "quic":
            rt = send_udp(args.tinc_ip, args.port, garbage)
            rn = send_udp(args.nginx_ip, args.port, garbage)
            match = (rt["close_type"] == rn["close_type"])
            print(f"GARBAGE quic ({len(garbage)} B): tinc={rt['close_type']}({rt['len']}B) nginx={rn['close_type']}({rn['len']}B) -> match={match}")
            sys.exit(0 if match else 1)
        elif args.proto == "obfs":
            rt = send_udp(args.tinc_ip, args.port, garbage)
            # Must look like a closed port: 0 bytes returned (silence)
            match = (rt["len"] == 0 and rt["close_type"] == "silence")
            print(f"GARBAGE obfs ({len(garbage)} B): tinc={rt['close_type']}({rt['len']}B) -> silence={match}")
            sys.exit(0 if match else 1)

    elif args.mode == "replay":
        # Replay at +wait_short
        print(f"Waiting {args.wait_short:.1f}s for short replay window...")
        time.sleep(args.wait_short)

        if args.proto == "https":
            rt1 = send_tcp(args.tinc_ip, args.port, payload)
            rn1 = send_tcp(args.nginx_ip, args.port, payload)
            match1 = (rt1["close_type"] == rn1["close_type"]) and (abs(rt1["len"] - rn1["len"]) < 32)
            print(f"REPLAY +{args.wait_short:.1f}s https: tinc={rt1['close_type']}({rt1['len']}B) nginx={rn1['close_type']}({rn1['len']}B) -> match={match1}")

            delay_rem = max(0.0, args.wait_long - args.wait_short)
            print(f"Waiting {delay_rem:.1f}s for long replay window (+{args.wait_long:.1f}s)...")
            time.sleep(delay_rem)

            rt2 = send_tcp(args.tinc_ip, args.port, payload)
            rn2 = send_tcp(args.nginx_ip, args.port, payload)
            match2 = (rt2["close_type"] == rn2["close_type"]) and (abs(rt2["len"] - rn2["len"]) < 32)
            print(f"REPLAY +{args.wait_long:.1f}s https: tinc={rt2['close_type']}({rt2['len']}B) nginx={rn2['close_type']}({rn2['len']}B) -> match={match2}")

            sys.exit(0 if (match1 and match2) else 1)

        elif args.proto == "quic":
            rt1 = send_udp(args.tinc_ip, args.port, payload)
            rn1 = send_udp(args.nginx_ip, args.port, payload)
            match1 = (rt1["close_type"] == rn1["close_type"]) and (abs(rt1["len"] - rn1["len"]) < 16)
            print(f"REPLAY +{args.wait_short:.1f}s quic: tinc={rt1['close_type']}({rt1['len']}B) nginx={rn1['close_type']}({rn1['len']}B) -> match={match1}")

            delay_rem = max(0.0, args.wait_long - args.wait_short)
            print(f"Waiting {delay_rem:.1f}s for long replay window (+{args.wait_long:.1f}s)...")
            time.sleep(delay_rem)

            rt2 = send_udp(args.tinc_ip, args.port, payload)
            rn2 = send_udp(args.nginx_ip, args.port, payload)
            match2 = (rt2["close_type"] == rn2["close_type"]) and (abs(rt2["len"] - rn2["len"]) < 16)
            print(f"REPLAY +{args.wait_long:.1f}s quic: tinc={rt2['close_type']}({rt2['len']}B) nginx={rn2['close_type']}({rn2['len']}B) -> match={match2}")

            sys.exit(0 if (match1 and match2) else 1)

        elif args.proto == "obfs":
            rt1 = send_udp(args.tinc_ip, args.port, payload)
            match1 = (rt1["len"] == 0 and rt1["close_type"] == "silence")
            print(f"REPLAY +{args.wait_short:.1f}s obfs: tinc={rt1['close_type']}({rt1['len']}B) -> silence={match1}")

            delay_rem = max(0.0, args.wait_long - args.wait_short)
            print(f"Waiting {delay_rem:.1f}s for long replay window (+{args.wait_long:.1f}s)...")
            time.sleep(delay_rem)

            rt2 = send_udp(args.tinc_ip, args.port, payload)
            match2 = (rt2["len"] == 0 and rt2["close_type"] == "silence")
            print(f"REPLAY +{args.wait_long:.1f}s obfs: tinc={rt2['close_type']}({rt2['len']}B) -> silence={match2}")

            sys.exit(0 if (match1 and match2) else 1)

if __name__ == "__main__":
    main()
