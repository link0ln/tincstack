#!/usr/bin/env python3
"""A stand-in for the Cloudflare API, for testing `tinc cert` without an account.

It implements exactly the four endpoints acme.c calls, and it turns a created
TXT record into a real DNS answer by forwarding it to pebble-challtestsrv --
so the ACME server validates against the record this mock was asked to write,
the same way it would against the real Cloudflare.

The bearer token selects the scenario, so one server covers the whole error
taxonomy:

    tok-good-...   everything works; zone example.test
    tok-bad        401 Invalid API Token            -> ACME_ERR_CF_TOKEN
    tok-inactive   verify succeeds, status "disabled" -> ACME_ERR_CF_TOKEN
    tok-noperm     verify succeeds, zone reads 403  -> ACME_ERR_CF_PERMISSION
    tok-otherzone  verify succeeds, only other.test visible -> ACME_ERR_CF_ZONE
    tok-nozone     verify succeeds, no zones at all -> ACME_ERR_CF_ZONE
    tok-ratelimit  429 on the zone read             -> ACME_ERR_CF_API
    tok-silent     TXT accepted but never published -> ACME_ERR_CHALLENGE

Standard library only: this runs in a plain python image, nothing is installed.
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHALLTESTSRV = os.environ.get("CHALLTESTSRV", "http://challtestsrv:8055")
ZONE_NAME = os.environ.get("ZONE_NAME", "example.test")
ZONE_ID = "zone000000000000000000000000000f"
OTHER_ZONE = {"id": "zone111111111111111111111111111f", "name": "other.test",
              "status": "active"}

records = {}   # record id -> {"name": fqdn, "content": value}


def challtestsrv(path, payload):
    req = urllib.request.Request(CHALLTESTSRV + path,
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def cf_error(code, message):
    return {"success": False, "errors": [{"code": code, "message": message}],
            "messages": [], "result": None}


def cf_ok(result):
    return {"success": True, "errors": [], "messages": [], "result": result}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("mock-cf %s - %s\n" % (self.address_string(), fmt % args))

    # -- plumbing ---------------------------------------------------------
    def token(self):
        """The scenario the bearer token selects.

        Real Cloudflare tokens are 40 characters and `tinc cert` refuses a
        short one before it ever calls out, so the test tokens are padded:
        only the first two dash-separated parts name the scenario.
        """
        auth = self.headers.get("Authorization", "")
        tok = auth[7:] if auth.startswith("Bearer ") else ""
        return "-".join(tok.split("-")[:2])

    def reply(self, status, doc):
        body = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    # -- endpoints --------------------------------------------------------
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        tok = self.token()

        if url.path == "/client/v4/user/tokens/verify":
            if tok == "tok-bad":
                return self.reply(401, cf_error(1000, "Invalid API Token"))
            if tok == "tok-inactive":
                return self.reply(200, cf_ok({"id": "t1", "status": "disabled"}))
            if not tok.startswith("tok-"):
                return self.reply(400, cf_error(6003, "Invalid request headers"))
            return self.reply(200, cf_ok({"id": "t1", "status": "active"}))

        if url.path == "/client/v4/zones":
            if tok == "tok-noperm":
                return self.reply(403, cf_error(9109,
                                                "Unauthorized to access requested resource"))
            if tok == "tok-ratelimit":
                return self.reply(429, cf_error(971, "Too many requests"))

            q = urllib.parse.parse_qs(url.query)
            name = (q.get("name") or [None])[0]

            if tok == "tok-nozone":
                return self.reply(200, cf_ok([]))
            if tok == "tok-otherzone":
                return self.reply(200, cf_ok([] if name else [OTHER_ZONE]))

            zone = {"id": ZONE_ID, "name": ZONE_NAME, "status": "active"}
            if name is None:
                return self.reply(200, cf_ok([zone]))
            return self.reply(200, cf_ok([zone] if name == ZONE_NAME else []))

        return self.reply(404, cf_error(7003, "Could not route to " + url.path))

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        body = self.read_body()

        if url.path == "/client/v4/zones/%s/dns_records" % ZONE_ID:
            try:
                rec = json.loads(body)
            except ValueError:
                return self.reply(400, cf_error(6003, "Invalid JSON in request body"))
            if rec.get("type") != "TXT":
                return self.reply(400, cf_error(9005, "Only TXT is mocked"))

            rid = uuid.uuid4().hex
            records[rid] = rec
            host = rec["name"].rstrip(".") + "."

            # tok-silent accepts the write and publishes nothing: this is what a
            # zone served by a different nameserver looks like from here.
            if self.token() != "tok-silent":
                try:
                    challtestsrv("/set-txt", {"host": host, "value": rec["content"]})
                except urllib.error.URLError as e:
                    return self.reply(500, cf_error(1000, "challtestsrv: %s" % e))

            return self.reply(200, cf_ok({"id": rid, "name": rec["name"],
                                          "type": "TXT", "content": rec["content"],
                                          "zone_id": ZONE_ID, "zone_name": ZONE_NAME}))

        return self.reply(404, cf_error(7003, "Could not route to " + url.path))

    def do_DELETE(self):
        url = urllib.parse.urlparse(self.path)
        prefix = "/client/v4/zones/%s/dns_records/" % ZONE_ID

        if url.path.startswith(prefix):
            rid = url.path[len(prefix):]
            rec = records.pop(rid, None)
            if rec is None:
                return self.reply(404, cf_error(81044, "Record not found"))
            try:
                challtestsrv("/clear-txt", {"host": rec["name"].rstrip(".") + "."})
            except urllib.error.URLError:
                pass
            return self.reply(200, cf_ok({"id": rid}))

        return self.reply(404, cf_error(7003, "Could not route to " + url.path))


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.environ.get("CERT", "/certs/mock-cf.pem"),
                        os.environ.get("KEY", "/certs/mock-cf.key"))
    srv = ThreadingHTTPServer(("0.0.0.0", 4443), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    sys.stderr.write("mock-cf listening on 4443, zone %s\n" % ZONE_NAME)
    srv.serve_forever()


if __name__ == "__main__":
    main()
