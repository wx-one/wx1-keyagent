# Stands in for the KBS admin API in test/local.sh: takes the resource policy
# the agent sets and writes it to /out/policy.rego. Test tooling only.
import base64, json
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        ok = self.headers.get("Authorization") == "Bearer kbs-secret"
        if ok:
            p = json.loads(body)["policy"]
            with open("/out/policy.rego", "w") as f:
                f.write(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode())
        self.send_response(200 if ok else 401)
        self.end_headers()

    def log_message(self, *a):
        pass

HTTPServer(("0.0.0.0", 8090), H).serve_forever()
