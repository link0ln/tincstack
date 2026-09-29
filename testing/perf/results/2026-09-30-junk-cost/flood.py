import os, socket, sys, time
host, port, dur = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
rate = float(sys.argv[4])  # pps; 0 = as fast as possible
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((host, port))
payload = bytearray(os.urandom(1300))
payload[0] &= 0x3f  # not 0x40+ (QUIC short) and not 0xc0+ (QUIC long); not SF magic
sent = 0
end = time.monotonic() + dur
if rate > 0:
    interval = 1.0 / rate
    nxt = time.monotonic()
    while time.monotonic() < end:
        try:
            s.send(payload); sent += 1
        except OSError:
            pass
        nxt += interval
        d = nxt - time.monotonic()
        if d > 0:
            time.sleep(d)
else:
    # max rate; refresh a few bytes occasionally so it is not one cached frame
    while time.monotonic() < end:
        for _ in range(2000):
            try:
                s.send(payload); sent += 1
            except OSError:
                pass
        if time.monotonic() >= end:
            break
print(sent)
