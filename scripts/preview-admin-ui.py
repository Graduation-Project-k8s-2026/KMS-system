#!/usr/bin/env python3
"""관리 화면(v2)을 서버 없이 브라우저로 미리 보는 도구. 가짜 API(메모리 데이터)와 정적 화면을 127.0.0.1에서 서빙한다.

  python3 scripts/preview-admin-ui.py [--port 8099] [--role admin|viewer] [--sealed]
  브라우저에서 http://127.0.0.1:8099/v2/ 를 연다.

실제 KMS·클러스터에 연결하지 않고, 값은 모두 가짜 예시다(주소·토큰·키 자료 없음). 키 상태 버튼(사용 중지/삭제 예약 등)은 메모리에서만 바뀐다.
"""
import argparse, datetime, hashlib, json, pathlib, re, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UI = pathlib.Path(__file__).resolve().parents[1] / "internal" / "adminapi" / "ui2"
NOW = datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_key(name, versions=1, state="active", rotate=0, min_v=1):
    vs = [{"Version": i + 1, "CreatedAt": iso(NOW - datetime.timedelta(days=30 * (versions - i)))} for i in range(versions)]
    m = {"Name": name, "Type": "aes256-gcm", "CreatedAt": vs[0]["CreatedAt"], "LatestVersion": versions, "MinDecryptionVersion": min_v,
         "AutoRotatePeriodSec": rotate, "LastRotatedAt": vs[-1]["CreatedAt"], "Versions": vs, "state": state}
    return m


class State:
    def __init__(self, role, sealed):
        self.role, self.sealed = role, sealed
        self.keys = {m["Name"]: m for m in [make_key("k8s-secrets", 2, rotate=7776000), make_key("demo", 3, rotate=2592000, min_v=2),
                                           make_key("campus-shipping", 1), make_key("kms-external.orders", 1),
                                           make_key("old-test", 1, state="disabled"),
                                           dict(make_key("temp-key", 1, state="pending_deletion"), deletion_date=iso(NOW + datetime.timedelta(days=12)))]}
        self.protected = ["k8s-secrets"]
        self.jobs, self.results = [], {}
        for i, (conc, rps) in enumerate([(1, 220), (4, 790), (16, 2104), (16, 1500)]):
            self.add_job(conc, rps, 1024, "transit", NOW - datetime.timedelta(hours=5 - i))

    def add_job(self, conc, rps, payload, mode, when):
        rid = hashlib.sha256(("%s-%s-%s" % (when.timestamp(), conc, rps)).encode()).hexdigest()[:32]
        self.jobs.append({"run_id": rid, "spec": {"mode": mode, "scenario": "basic", "op": "roundtrip", "count": 2000, "concurrency": conc, "payload_bytes": payload, "duration_seconds": 0},
                          "state": "succeeded", "upload": "stored", "created_at": iso(when), "service_account": "bench-transit"})
        n = 2000
        self.results[rid] = {"run_id": rid, "mode": mode, "requests": n, "errors": 0 if rps > 300 else 3, "started_at": iso(when), "ended_at": iso(when + datetime.timedelta(seconds=n / rps)),
                             "p50_seconds": 0.8 * conc / rps, "p95_seconds": 1.6 * conc / rps, "p99_seconds": 2.4 * conc / rps}


def audit_rows():
    rows = []
    def add(src, mins, subj, action, ok, **kw):
        r = {"utc": iso(NOW - datetime.timedelta(minutes=mins)), "request_id": "%016x" % (len(rows) + 1), "subject": subj, "action": action, "allowed": ok, "success": ok, "source": src}
        r.update(kw); rows.append(r)
    add("admin", 50, "admin-user", "POST /v1/keys completed", True, key="demo")
    add("admin", 40, "admin-user", "POST /v1/keys/disable completed", True, key="old-test")
    add("admin", 35, "viewer-user", "POST /v1/keys/rotate completed", False, key="demo")
    add("transit", 20, "system:serviceaccount:kms-demo:app-a", "encrypt", True, key="demo", listener="internal", status=200, latency_ms=1.4)
    add("transit", 19, "system:serviceaccount:kms-demo:app-a", "decrypt", True, key="demo", listener="internal", status=200, latency_ms=1.1)
    add("transit", 18, "system:serviceaccount:kms-demo:app-a", "encrypt", False, key="campus-shipping", listener="internal", status=403, latency_ms=0.4)
    add("transit", 10, "system:serviceaccount:kms-external:alice", "datakey", True, key="kms-external.orders", listener="external", client_ip="203.0.113.7", status=200, latency_ms=2.0)
    add("transit", 9, "system:serviceaccount:kms-demo:app-a", "encrypt", False, key="kms-external.orders", listener="external", client_ip="198.51.100.4", status=403, latency_ms=0.3)
    return rows


def prom_matrix(window):
    span = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400}.get(window, 900)
    step = {"15m": 15, "1h": 60, "6h": 300, "24h": 900}.get(window, 15)
    end = int(time.time())
    vals = [[t, str(20 + 10 * ((t // step) % 7))] for t in range(end - span, end, step)]
    return {"status": "success", "data": {"resultType": "matrix", "result": [{"metric": {"code": "200"}, "values": vals}]}}


def make_handler(st):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def send(self, code, obj=None, ctype="application/json", raw=None):
            body = raw if raw is not None else json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)

        def err(self, code, ecode, msg):
            self.send(code, {"error": ecode, "message": msg})

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            try: return json.loads(self.rfile.read(n) or b"{}")
            except ValueError: return {}

        def do_GET(self):
            path, _, q = self.path.partition("?")
            if path in ("/", "/v2"): self.send_response(302); self.send_header("Location", "/v2/"); self.end_headers(); return
            if path.startswith("/v2/"):
                f = UI / (path[4:] or "index.html")
                if not f.is_file(): return self.err(404, "not_found", "not found")
                ctype = {"html": "text/html", "js": "application/javascript", "css": "text/css"}.get(f.suffix[1:], "text/plain") + "; charset=utf-8"
                return self.send(200, raw=f.read_bytes(), ctype=ctype)
            if path == "/api/session": return self.send(200, {"role": st.role, "user": "preview@example.test", "csrf_token": "preview-token"})
            if path == "/v1/sys/seal-status":
                return self.send(200, {"initialized": True, "migration_required": False, "sealed": st.sealed, "seal_type": "shamir", "recovery_available": False, "progress": "0/3" if st.sealed else ""})
            if path == "/v1/sys/seal-profile":
                return self.send(200, {"Type": "shamir", "RequiresHumans": True, "HumanCount": 3, "SinglePointOfFailure": False, "HardwareDependent": False, "AutoUnsealCapable": False, "Notes": "자동 unseal 불가 — 조각을 사람이 여러 번 제출해야 함"})
            if path == "/api/info": return self.send(200, {"server_version": "preview", "source_sha": "0" * 40, "bench_image": "x@sha256:" + "a" * 64, "admin_image": "x@sha256:" + "b" * 64, "audit_enabled": True, "protected_keys": st.protected})
            if st.sealed and path.startswith("/v1/keys"): return self.err(503, "sealed", "kms is sealed")
            if path == "/v1/keys": return self.send(200, {"keys": sorted(st.keys)})
            m = re.fullmatch(r"/v1/keys/([^/]+)", path)
            if m:
                k = st.keys.get(m.group(1))
                return self.send(200, k) if k else self.err(404, "key_not_found", "key not found")
            if path == "/api/audit": return self.send(200, audit_rows())
            if path == "/api/console-users": return self.send(200, [{"user": "pre***@example.test", "role": "admin"}, {"user": "vie***@example.test", "role": "viewer"}])
            if path == "/api/jobs": return self.send(200, st.jobs)
            m = re.fullmatch(r"/api/bench/results/(\w+)", path)
            if m: return self.send(200, st.results[m.group(1)]) if m.group(1) in st.results else self.err(404, "not_found", "no result")
            if path == "/api/dashboard/metrics":
                params = dict(p.split("=", 1) for p in q.split("&") if "=" in p)
                if params.get("range") == "1":
                    if params.get("window", "") not in ("", "15m", "1h", "6h", "24h"): return self.err(400, "bad_request", "unknown window")
                    return self.send(200, prom_matrix(params.get("window", "")))
                return self.send(200, {"status": "success", "data": {"resultType": "vector", "result": [{"metric": {"code": "200"}, "value": [time.time(), "31.5"]}]}})
            self.err(404, "not_found", "not found")

        def do_POST(self):
            path = self.path.split("?")[0]
            if st.role != "admin": return self.err(403, "forbidden", "admin required")
            b = self.body()
            if path == "/v1/keys":
                n = b.get("name", "")
                if n in st.keys: return self.err(409, "key_exists", "key already exists")
                st.keys[n] = make_key(n); return self.send(201, st.keys[n])
            m = re.fullmatch(r"/v1/keys/([^/]+)/(\w[\w-]*)", path)
            if m and m.group(1) in st.keys:
                k, op = st.keys[m.group(1)], m.group(2)
                if op in ("disable", "schedule-deletion") and k["Name"] in st.protected:
                    return self.err(409, "key_protected", "the key is protected and cannot be disabled or deleted")
                if op == "disable": k["state"] = "disabled"
                elif op == "enable": k["state"] = "active"
                elif op == "schedule-deletion":
                    d = int(b.get("pending_days") or 30)
                    if not 7 <= d <= 30: return self.err(400, "invalid_request", "pending_days must be between 7 and 30")
                    k["state"], k["deletion_date"] = "pending_deletion", iso(NOW + datetime.timedelta(days=d))
                elif op == "cancel-deletion": k["state"] = "disabled"; k.pop("deletion_date", None)
                elif op == "rotate":
                    k["LatestVersion"] += 1; k["Versions"].append({"Version": k["LatestVersion"], "CreatedAt": iso(NOW)})
                elif op == "config": k["MinDecryptionVersion"] = b.get("min_decryption_version", k["MinDecryptionVersion"])
                return self.send(200, k)
            if path == "/api/jobs":
                st.add_job(int(b.get("concurrency", 1)), 500, int(b.get("payload_bytes", 1024)), b.get("mode", "transit"), datetime.datetime.now(datetime.timezone.utc))
                return self.send(201, st.jobs[-1])
            self.err(404, "not_found", "not found")

        def do_DELETE(self): self.err(404, "not_found", "not found")
    return H


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, default=8099)
    p.add_argument("--role", choices=["admin", "viewer"], default="admin")
    p.add_argument("--sealed", action="store_true")
    a = p.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(State(a.role, a.sealed)))
    print("미리보기: http://127.0.0.1:%d/v2/  (역할 %s, 가짜 데이터)  종료: Ctrl+C" % (a.port, a.role), file=sys.stderr)
    try: srv.serve_forever()
    except KeyboardInterrupt: pass


if __name__ == "__main__":
    main()
