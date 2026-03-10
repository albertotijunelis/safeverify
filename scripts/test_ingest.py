"""Quick E2E test for ingest — run while server is up on port 8099."""
import json
import time
import urllib.request
import urllib.parse

data = urllib.parse.urlencode({
    "source": "recent", "limit": "5",
    "tag": "", "file_type": "exe", "directory": "",
}).encode()
req = urllib.request.Request(
    "http://127.0.0.1:8099/api/ingest/start", data=data, method="POST"
)
r = urllib.request.urlopen(req)
d = json.loads(r.read())
print("Start:", json.dumps(d))

if d.get("started"):
    for _ in range(60):
        time.sleep(5)
        r2 = urllib.request.urlopen("http://127.0.0.1:8099/api/ingest/status")
        s = json.loads(r2.read())
        elapsed = s["elapsed_seconds"]
        status = s["status"]
        dl = s["downloaded"]
        an = s["analysed"]
        fa = s["failed"]
        sk = s["skipped_existing"]
        sha = s.get("current_sha256", "")[:16]
        print(f"[{elapsed}s] {status} | dl:{dl} ok:{an} fail:{fa} skip:{sk} | {sha}")
        if status in ("done", "error"):
            if s.get("errors"):
                print("Errors:", s["errors"][:5])
            break
