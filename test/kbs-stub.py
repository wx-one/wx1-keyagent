# Stands in for the KBS admin API in test/local.sh: takes the resource policy
# the agent sets and writes it to /out/policy.rego, and the resources it
# writes (the vTPM state keys) to /out/resources/<path>. Test tooling only.
import base64, json, os
from http.server import BaseHTTPRequestHandler, HTTPServer

# the test's directory is the host user's: what is written here they can remove
os.umask(0)

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        status = 200 if self.headers.get("Authorization") == "Bearer kbs-secret" else 401
        if status == 200 and self.path == "/kbs/v0/resource-policy":
            p = json.loads(body)["policy"]
            with open("/out/policy.rego", "w") as f:
                f.write(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode())
        elif status == 200 and self.path.startswith("/kbs/v0/resource/"):
            parts = self.path[len("/kbs/v0/resource/"):].split("/")
            if len(parts) != 3 or any(p in ("", ".", "..") for p in parts):
                status = 400
            else:
                os.makedirs(os.path.join("/out/resources", *parts[:2]), exist_ok=True)
                with open(os.path.join("/out/resources", *parts), "wb") as f:
                    f.write(body)
        elif status == 200:
            status = 404
        self.send_response(status)
        self.end_headers()

    def log_message(self, *a):
        pass

HTTPServer(("0.0.0.0", 8090), H).serve_forever()
