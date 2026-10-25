"""Protocol smoke test (use LLM_PROVIDER=mock).  URL=http://localhost:8000/ python selftest.py"""
import os, json, hmac, hashlib, httpx

U = os.environ.get("URL", "http://localhost:8000/")
KEY = "test-secret-key"
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m)
c = httpx.Client(timeout=60)

ds = [{"dossierId": f"d{i}", "lines": [{"id": "L1", "text": "hello"}]} for i in range(5)]
req = {"operation": "propose", "evaluationId": "ev1", "receiptKey": KEY, "dossiers": ds}
r = c.post(U, json=req)
ok(r.status_code == 200 and r.json()["status"] == "awaiting_receipts", "propose")
ok(c.post(U, json=req).content == r.content, "byte-exact propose replay")
ok(c.post(U, json={**req, "dossiers": ds[:3]}).status_code == 409, "changed content -> 409")
ok(c.post(U, json={"operation": "nope"}).status_code == 400, "invalid operation")
ok(c.post(U, json={**req, "evaluationId": "ev2", "dossiers": [ds[0], ds[0]]}).status_code == 400, "duplicate dossier ids")
ok(c.post(U, content=b"{bad").status_code == 400, "malformed JSON")

props = r.json()["proposals"]
def receipt(p, key=KEY):
    body = {"callId": p["callId"], "action": p["action"], "proposalDigest": p["proposalDigest"], "receiptId": "r-" + p["callId"]}
    body["signature"] = hmac.new(key.encode(), canon(body).encode(), hashlib.sha256).hexdigest()
    return body
bad = [receipt(p, "wrong-key") for p in props]
ok(c.post(U, json={"operation": "commit", "evaluationId": "ev1", "receipts": bad}).status_code == 400, "forged signature rejected")
good = [receipt(p) for p in props]
ok(c.post(U, json={"operation": "commit", "evaluationId": "nope", "receipts": good}).status_code == 404, "unknown evaluation")
tampered = [{**good[0], "action": "no_action" if props[0]["action"] != "no_action" else "create_draft"}] + good[1:]
ok(c.post(U, json={"operation": "commit", "evaluationId": "ev1", "receipts": tampered}).status_code == 400, "action mismatch rejected")
cm = {"operation": "commit", "evaluationId": "ev1", "receipts": good}
r2 = c.post(U, json=cm)
ok(r2.status_code == 200 and r2.json()["status"] == "completed", "commit completed")
ok(c.post(U, json=cm).content == r2.content, "byte-exact commit replay")
ok(c.post(U, json={**cm, "receipts": good[:2]}).status_code == 409, "changed commit -> 409")
