#!/usr/bin/env python3
"""UI 미리보기 서버 (개발용, 배포 안 함). 표준 라이브러리만 사용.

기존 화면(/console, /dashboard)과 새 화면(/v2/)을 디스크의 실제 파일로 서빙하고,
화면이 부르는 API는 가짜 JSON으로 응답한다(형식은 실제 Go 코드의 JSON과 같게 맞춤).
  /compare            왼쪽 기존 / 오른쪽 새 화면 나란히 비교
  ?sealed=1 ?role=viewer  상태·역할 전환 (주소 쿼리가 화면의 모든 API 호출에 자동으로 붙음)
  ?seal=tpm|k8s|dev    봉인 방식별 Seal 특성 표 확인
  ?err=404            키/작업 API를 그 상태 코드로 실패시킴(오류 문구 확인)
  주소에 sealed가 없으면 [봉인하기]·[조각 제출]이 서버 상태를 실제로 바꾼다(조각 3개면 해제)
실행: python3 tools/ui-preview/serve.py --port 8088
"""
import argparse, json, math, mimetypes, re, time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parents[2]
CONSOLE = ROOT / "internal/api/console/console.html"
OPERATIONS = ROOT / "internal/adminapi/operations.html"
UI2 = ROOT / "internal/adminapi/ui2"

NOW = datetime.now(timezone.utc)
def iso(days_ago): return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

# 키 메타: internal/keys/types.go의 KeyRingMeta (json 태그 없음 → 대문자 필드명)
KEYS = {
    "campus-shipping": {"latest": 3, "min": 3, "auto": 7776000, "created": 40, "rotated": 3},
    "demo": {"latest": 2, "min": 1, "auto": 0, "created": 150, "rotated": 120},   # 90일 넘음 → 주황 경고
    "k8s-secrets": {"latest": 2, "min": 1, "auto": 2592000, "created": 60, "rotated": 45},
}
def key_meta(name):
    k = KEYS[name]
    return {"Name": name, "Type": "aes256-gcm96", "CreatedAt": iso(k["created"]), "LatestVersion": k["latest"],
            "MinDecryptionVersion": k["min"], "AutoRotatePeriodSec": k["auto"], "LastRotatedAt": iso(k["rotated"]),
            "Versions": [{"Version": v, "CreatedAt": iso(k["created"] - (k["created"] - k["rotated"]) * (v - 1) / max(1, k["latest"] - 1))} for v in range(1, k["latest"] + 1)]}

def audit_events():  # internal/audit: utc, request_id, subject, action, allowed, success
    acts = ["GET /v1/keys", "POST /v1/keys", "POST /v1/sys/unseal", "GET /api/jobs", "POST /api/jobs", "GET /v1/sys/seal-status"]
    out = []
    for i in range(40):
        bad = i % 9 == 4
        out.append({"utc": (NOW - timedelta(minutes=6 * i)).strftime("%Y-%m-%dT%H:%M:%SZ"), "request_id": "req-%04d" % (900 - i),
                    "subject": ["admin@example.test", "viewer@example.test", "ops@example.test"][i % 3],
                    "action": acts[i % 6] + (" requested" if i % 2 else " completed"), "allowed": not (bad and i % 2), "success": not bad})
    return out

JOBS = []  # 시작 버튼으로 추가됨. 새 실행은 2초 뒤 running, 6초 뒤 최종 상태(3초·2초 갱신 확인용)
def _seed():
    for i, (mode, st, c) in enumerate([("transit", "succeeded", 1), ("transit", "succeeded", 16), ("plugin", "succeeded", 4), ("e2e", "failed", 1)], 1):
        JOBS.append({"id": "a%d%07x" % (i, i * 4099), "mode": mode, "conc": c, "count": 100 * i, "dur": 0, "payload": 1024,
                     "created": NOW - timedelta(hours=i * 2), "final": st})
_seed()

def _state(j):
    age = (datetime.now(timezone.utc) - j["created"]).total_seconds()
    state = "queued" if age < 2 else "running" if age < 6 else j["final"]
    upload = "stored" if state == "succeeded" and age >= 7 else ("pending" if state in ("queued", "running", "succeeded") else "failed")
    return state, upload

def job_json(j):  # internal/jobs Run
    state, upload = _state(j)
    return {"run_id": j["id"], "spec": {"mode": j["mode"], "scenario": "basic", "op": "roundtrip", "count": j["count"], "concurrency": j["conc"],
            "payload_bytes": j["payload"], "duration_seconds": j["dur"]}, "namespace": "kms-bench", "state": state, "upload": upload,
            "created_at": j["created"].strftime("%Y-%m-%dT%H:%M:%SZ")}

def jobs():
    return sorted((job_json(j) for j in JOBS), key=lambda r: r["created_at"], reverse=True)

def bench_result(rid):  # internal/jobs Result. 동시성이 높을수록 처리량↑ 지연↑ (비교 그래프 확인용)
    j = next((x for x in JOBS if x["id"] == rid), JOBS[0])
    c = j["conc"]; rps = 180 * (c ** 0.6); secs = float(j["dur"] or max(2.0, j["count"] / rps)); n = int(rps * secs)
    start = j["created"] + timedelta(seconds=1); fmt = "%Y-%m-%dT%H:%M:%SZ"
    p50 = 0.0035 + 0.0006 * c
    return {"schema_version": 1, "run_id": rid, "mode": j["mode"], "requests": n, "success": n - c // 8, "errors": c // 8,
            "started_at": start.strftime(fmt), "ended_at": (start + timedelta(seconds=secs)).strftime(fmt),
            "p50_seconds": p50, "p95_seconds": p50 * 2.1, "p99_seconds": p50 * 3.2}

def prom(metric, ranged, sealed):
    if metric == "sealed":
        data = {"resultType": "vector", "result": [{"metric": {}, "value": [time.time(), "1" if sealed else "0"]}]}
    elif metric == "requests" and ranged:
        now = int(time.time()); vals = []
        for i in range(61):
            t = now - (60 - i) * 15
            vals.append([t, "%.3f" % (0 if sealed else 18 + 6 * math.sin(i / 6) + (i % 5))])
        data = {"resultType": "matrix", "result": [{"metric": {"code": "200"}, "values": vals}]}
    elif metric == "requests":
        data = {"resultType": "vector", "result": [] if sealed else [
            {"metric": {"code": "200"}, "value": [time.time(), "21.40"]}, {"metric": {"code": "500"}, "value": [time.time(), "0.21"]}]}
    elif metric == "targets":
        data = {"resultType": "vector", "result": [{"metric": {"job": "kms"}, "value": [time.time(), "1"]}]}
    else:
        data = {"resultType": "vector", "result": [{"metric": {}, "value": [time.time(), str(int(time.time()) - 3600)]}]}
    return {"status": "success", "data": data}

COMPARE = """<!doctype html><html lang="ko"><meta charset="utf-8"><title>UI 비교</title>
<style>
body{margin:0;font:15px system-ui,sans-serif;background:#f3f4f6;height:100vh;display:flex;flex-direction:column}
.bar{display:flex;gap:1.2rem;align-items:center;padding:.6rem 1rem;background:#fff;border-bottom:1px solid #d1d5db}
.bar b{font-size:1rem} select,button{font:inherit;padding:.25rem .5rem}
.cols{flex:1;display:grid;grid-template-columns:1fr 1fr;gap:.6rem;padding:.6rem;min-height:0}
.col{display:flex;flex-direction:column;min-height:0}.col h3{margin:0 0 .3rem;font-size:.9rem;color:#4b5563}
iframe{flex:1;border:1px solid #d1d5db;background:#fff;width:100%}
</style>
<div class="bar"><b>UI 비교</b>
 <label>페이지 <select id="page"><option value="home">홈</option><option value="dashboard">대시보드</option><option value="keys">키</option><option value="seal">봉인</option><option value="ops">성능 시험</option><option value="audit">감사 로그</option></select></label>
 <label><input type="checkbox" id="sealed"> 봉인 상태</label>
 <label>역할 <select id="role"><option>admin</option><option>viewer</option></select></label>
</div>
<div class="cols"><div class="col"><h3>기존 (v1)</h3><iframe id="a"></iframe></div><div class="col"><h3>새 화면 (v2)</h3><iframe id="b"></iframe></div></div>
<script>
const V1={home:'/console',ops:'/dashboard',audit:'/dashboard',dashboard:'/dashboard',keys:'/console#keys-content',seal:'/console#init-area'};
function go(){const q='?sealed='+(sealed.checked?1:0)+'&role='+role.value,p=page.value;
 a.src=V1[p].replace(/(#|$)/,q+'$1');b.src='/v2/'+q+'#/'+p;}
['page','sealed','role'].forEach(i=>document.getElementById(i).onchange=go);
const u=new URLSearchParams(location.search);
if(u.get('page'))page.value=u.get('page');sealed.checked=u.get('sealed')==='1';if(u.get('role'))role.value=u.get('role');go();
</script></html>"""

GLOBAL = {"sealed": False, "progress": 0}

INJECT = """<script>(function(){var q=location.search.slice(1);if(!q)return;var f=window.fetch;
window.fetch=function(u,o){if(typeof u==='string'&&u.charAt(0)==='/'){u+=(u.indexOf('?')<0?'?':'&')+q;}return f.call(this,u,o);};})();</script>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def state(self, q):
        # 상태는 쿼리(?sealed=1&role=viewer)에서만 읽는다. HTML에 주입된 스크립트(INJECT)가
        # 화면의 모든 API 호출에 페이지 주소의 쿼리를 붙여 주므로 쿠키가 필요 없다.
        # 주소에 sealed가 있으면 그 값, 없으면 [봉인하기]/[조각 제출]로 바뀐 서버 상태(GLOBAL)를 쓴다.
        sealed = (q["sealed"][0] == "1") if "sealed" in q else GLOBAL["sealed"]
        return sealed, ("viewer" if q.get("role", ["admin"])[0] == "viewer" else "admin")

    def send(self, code, body, ctype="application/json"):
        if not isinstance(body, bytes):
            body = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text") else ""))
        self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(body)

    def page(self, path, q, sealed, role):
        html = path.read_bytes().decode("utf-8")
        # 화면 파일은 수정하지 않고, 서빙할 때만 스크립트를 끼워 넣는다.
        html = re.sub(r"(<head[^>]*>|<!doctype html>|<!DOCTYPE html>)", lambda m: m[1] + INJECT, html, count=1) if "<head" in html.lower() or "doctype" in html.lower() else INJECT + html
        self.send(200, html, "text/html")

    def fake_error(self, p, q):
        # ?err=404 처럼 붙이면 키 API가 그 상태 코드로 실패한다(오류 문구 확인용)
        code = int(q["err"][0]) if "err" in q and q["err"][0].isdigit() else 0
        if code and (p.startswith("/v1/") or p.startswith("/api/jobs")):
            self.send(code, {"error": "preview simulated error"}); return True
        return False

    def do_GET(self):
        u = urlparse(self.path); p = u.path; q = parse_qs(u.query); sealed, role = self.state(q)
        if self.fake_error(p, q): return
        if p == "/": return self.redirect("/compare")
        if p == "/compare": return self.send(200, COMPARE, "text/html")
        if p == "/console": return self.page(CONSOLE, q, sealed, role)
        if p == "/dashboard": return self.page(OPERATIONS, q, sealed, role)
        if p == "/v2": return self.redirect("/v2/" + ("?" + u.query if u.query else ""))
        if p.startswith("/v2/"):
            rel = p[4:] or "index.html"
            f = (UI2 / rel).resolve()
            if UI2 not in f.parents and f != UI2 or not f.is_file(): return self.send(404, "not found", "text/plain")
            if rel == "index.html": return self.page(f, q, sealed, role)
            return self.send(200, f.read_bytes(), mimetypes.guess_type(f.name)[0] or "application/octet-stream")
        if p == "/api/session": return self.send(200, {"role": role, "user": ("viewer@example.test" if role == "viewer" else "admin@example.test"), "csrf_token": "preview-token"})
        if p == "/v1/sys/seal-status":
            d = {"initialized": True, "migration_required": False, "sealed": sealed, "seal_type": q.get("seal", ["shamir"])[0]}
            if sealed and d["seal_type"] == "shamir": d["progress"] = "%d/3" % GLOBAL["progress"]
            return self.send(200, d)
        if p in ("/v1/keys", "/v1/keys/"):
            return self.send(503, {"error": "sealed"}) if sealed else self.send(200, {"keys": sorted(KEYS)})
        m = re.fullmatch(r"/v1/keys/([^/]+)", p)
        if m:
            if sealed: return self.send(503, {"error": "sealed"})
            return self.send(200, key_meta(m[1])) if m[1] in KEYS else self.send(404, {"error": "not found"})
        if p == "/api/audit": return self.send(200, audit_events())
        if p == "/api/jobs": return self.send(200, jobs())
        m = re.fullmatch(r"/api/jobs/([^/]+)", p)
        if m:
            j = next((x for x in JOBS if x["id"] == m[1]), None)
            return self.send(200, job_json(j)) if j else self.send(404, "run unavailable", "text/plain")
        if p == "/api/info":
            return self.send(200, {"server_version": "v0.9.0-preview", "source_sha": "0123456789abcdef0123456789abcdef01234567", "audit_enabled": True,
                                   "bench_image": "registry.example/kms-bench@sha256:" + "ab12cd34ef56" * 5 + "abcd", "admin_image": "registry.example/kms-admin@sha256:" + "9f8e7d6c5b4a" * 5 + "abcd"})
        if p == "/api/console-users":  # 서버가 이메일을 가려서 보낸다(원문 없음)
            return self.send(200, [{"user": "adm***@example.test", "role": "admin"}, {"user": "ops***@example.test", "role": "admin"}, {"user": "vie***@example.test", "role": "viewer"}])
        m = re.fullmatch(r"/api/bench/results/([^/]+)", p)
        if m: return self.send(200, bench_result(m[1]))
        if p == "/api/dashboard/metrics":
            return self.send(200, prom(q.get("metric", [""])[0], q.get("range", [""])[0] == "1", sealed))
        self.send(404, {"error": "not found"})

    def redirect(self, to):
        self.send_response(302); self.send_header("Location", to); self.end_headers(); return True

    def do_POST(self):
        sealed, role = self.state(parse_qs(urlparse(self.path).query))
        n = int(self.headers.get("Content-Length") or 0)
        try: body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError: body = {}
        p = urlparse(self.path).path
        if self.fake_error(p, parse_qs(urlparse(self.path).query)): return
        if role != "admin": return self.send(403, "admin required", "text/plain")
        if self.headers.get("X-CSRF-Token") != "preview-token": return self.send(403, "CSRF rejected", "text/plain")
        if p == "/v1/sys/unseal":
            GLOBAL["progress"] += 1
            if GLOBAL["progress"] >= 3: GLOBAL["sealed"], GLOBAL["progress"] = False, 0
            return self.send(200, {"sealed": GLOBAL["sealed"], "progress": "%d/3" % GLOBAL["progress"]})
        if p == "/v1/sys/seal":
            GLOBAL["sealed"], GLOBAL["progress"] = True, 0
            return self.send(200, {"sealed": True})
        if p in ("/v1/sys/init",): return self.send(409, {"error": "already initialized"})
        if p in ("/v1/keys", "/v1/keys/"):
            KEYS[body.get("name", "new-key")] = {"latest": 1, "min": 1, "auto": body.get("auto_rotate_period_sec", 0), "created": 0, "rotated": 0}
            return self.send(201, key_meta(body.get("name", "new-key")))
        m = re.fullmatch(r"/v1/keys/([^/]+)/(rotate|config)", p)
        if m and m[1] in KEYS:
            k = KEYS[m[1]]
            if m[2] == "rotate": k["latest"] += 1; k["rotated"] = 0
            else:
                if "min_decryption_version" in body: k["min"] = body["min_decryption_version"]
                if "auto_rotate_period_sec" in body: k["auto"] = body["auto_rotate_period_sec"]
            return self.send(200, key_meta(m[1]))
        if p == "/api/jobs":
            j = {"id": "b%07x" % (int(time.time() * 100) & 0xfffffff), "mode": body.get("mode", "transit"), "conc": body.get("concurrency", 1), "count": body.get("count", 100),
                 "dur": body.get("duration_seconds", 0), "payload": body.get("payload_bytes", 1024), "created": datetime.now(timezone.utc), "final": "succeeded"}
            JOBS.append(j)
            return self.send(201, job_json(j))
        self.send(404, {"error": "not found"})

    def do_DELETE(self): self.send(204, b"")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, default=8088)
    a = ap.parse_args()
    print("preview: http://127.0.0.1:%d/compare" % a.port)
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()
