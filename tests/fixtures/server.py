#!/usr/bin/env python3
"""Fixture server for the XSS scanner acceptance suite.

Every endpoint reflects `q` into a different context so the headless verifier
can be checked for both true execution and false positives.

    python3 tests/fixtures/server.py --port 8899
"""
import argparse
import html
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit


def esc(s):
    return html.escape(s, quote=True)


def page(title, inner):
    return ("<!doctype html><html><head><title>%s</title></head><body>%s</body></html>"
            % (title, inner)).encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "xssfixture/1"

    def log_message(self, *a):
        pass

    def _send(self, body, code=200, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        sp = urlsplit(self.path)
        qs = dict(parse_qsl(sp.query, keep_blank_values=True))
        q = qs.get("q", "")
        p = sp.path

        if p == "/pos/echo":
            self._send(page("echo", "<div>%s</div>" % q))
        elif p == "/pos/attr":
            self._send(page("attr", '<input type="text" value="%s">' % q))
        elif p == "/pos/jsbreak":
            self._send(page("js", '<script>var x = "%s";</script>' % q))
        elif p == "/neg/escaped":
            self._send(page("esc", "<div>%s</div>" % esc(q)))
        elif p == "/neg/json":
            payload = json.dumps({"q": q}).replace("</", "<\\/")
            self._send(page("json",
                            '<script type="application/json" id="__NEXT_DATA__">%s</script>'
                            % payload))
        elif p == "/neg/comment":
            self._send(page("comment", "<!-- echo: %s -->" % q))
        elif p == "/neg/textarea":
            self._send(page("ta", "<textarea>%s</textarea>" % q))
        elif p == "/neg/template":
            self._send(page("tmpl", "<template>%s</template>" % q))
        elif p == "/neg/jsstring":
            # single-quoted JS string with quotes/backslashes escaped
            v = q.replace("\\", "\\\\").replace("'", "\\'")
            self._send(page("jsstr", "<script>var x = '%s';</script>" % v))
        elif p == "/neg/wrongtoken":
            # payload is reflected raw, but no execution is possible: it lands
            # inside an attribute that never fires for our payload family
            self._send(page("attr-nofire", '<div data-x="%s"></div>' % esc(q)))
        elif p.startswith("/redirect/out/"):
            # target host comes from the path, so injecting q cannot change it
            seg = p.rsplit("/", 1)[-1]
            loc = "http://127.0.0.1:%s/landing" % (seg if seg.isdigit() else "1")
            self._send(b"", code=302, ctype="text/plain", extra={"Location": loc})
        else:
            self._send(page("home", '<a href="/pos/echo?q=1">echo</a>'))

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self._send(page("post", "<div>posted</div>"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--bind", default="127.0.0.1")
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    print("listening on http://%s:%d" % (a.bind, a.port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
