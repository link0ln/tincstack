#!/usr/bin/env python3
"""Size thresholds of a QUIC server's Version Negotiation and stateless
resets: which datagram sizes and id lengths it answers, how long the answer
is, the first byte, and whether a burst is rate-limited. Standard library
only. Usage: quic_thresholds.py <server ip> (port 443)
"""
import os, socket, struct, sys, collections
host=sys.argv[1]
def send(p, wait=0.4):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(wait); s.sendto(p,(host,443)); out=[]
    try:
        while True: out.append(s.recvfrom(65535)[0])
    except socket.timeout: pass
    s.close(); return out
def lh(v,dl=8,sl=8): return bytes([0xc0])+struct.pack(">I",v)+bytes([dl])+os.urandom(dl)+bytes([sl])+os.urandom(sl)
print("VN by size:")
for n in (7,20,23,43,100,600,1000,1199,1200,1500):
    b=lh(0x1a2a3a4a); b=(b+os.urandom(max(0,n-len(b))))[:n] if n>=len(b) else b[:n]
    r=send(b); print(" ",n, [ (len(x), x[0]) for x in r])
print("VN dcid len 0/1/20/21, scid 0:")
for dl in (0,1,20,21):
    b=lh(0x1a2a3a4a,dl,0); b+=os.urandom(1200-len(b)); r=send(b); print(" ",dl,[len(x) for x in r])
print("reset by size (5 tries each): lengths")
for n in (20,21,22,23,30,42,43,44,50,100,400,1200,1500):
    L=[]
    for _ in range(5):
        r=send(bytes([0x40|(os.urandom(1)[0]&0x3f)])+os.urandom(n-1))
        L.append(",".join("%d/%02x"%(len(x),x[0]) for x in r) or "-")
    print(" ",n,L)
print("burst: 30 resets fast (count answered)")
c=0
for _ in range(30):
    c+= bool(send(bytes([0x40])+os.urandom(99),0.1))
print(" ",c)
print("long header v1 handshake type, unknown dcid 1200:", [len(x) for x in send(bytes([0xe0])+struct.pack('>I',1)+bytes([20])+os.urandom(20)+bytes([0])+os.urandom(1170))])
