"""Try to take a port the way a second Windows process could.

    python win-bind-probe.py <tcp|udp> <port>

Binds 0.0.0.0:<port> with SO_REUSEADDR (and listens, for TCP) and prints
TAKEN, or REFUSED <winerror>. On Windows, SO_REUSEADDR lets such a socket bind
a port another process already holds unless that holder set
SO_EXCLUSIVEADDRUSE. Run by windows-wine-test.sh with Windows Python under
Wine.
"""
import socket
import sys

kind = socket.SOCK_STREAM if sys.argv[1] == "tcp" else socket.SOCK_DGRAM
s = socket.socket(socket.AF_INET, kind)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", int(sys.argv[2])))
    if kind == socket.SOCK_STREAM:
        s.listen(1)
    print("TAKEN", flush=True)
except OSError as e:
    print("REFUSED", getattr(e, "winerror", None) or e.errno, flush=True)
