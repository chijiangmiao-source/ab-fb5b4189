"""One-shot verification: build check, unit tests, HTTP smoke scenarios.

Runs inside the Compose `verify` service against the `app` service and
exits 0 only when every check passes. The three mandated scenarios are
covered both as unit tests and as HTTP smoke checks:

  * complete          完整切换
  * corrupt-complete  完成标记损坏
  * retain-old        旧有效槽保留
"""
from __future__ import annotations

import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []


def report(name, ok, detail=""):
    RESULTS.append((name, ok))
    tag = "PASS" if ok else "FAIL"
    line = f"[{tag}] {name}"
    if detail and not ok:
        line += f" -- {detail}"
    print(line, flush=True)


def step_build_check():
    import compileall

    ok = compileall.compile_dir(os.path.join(ROOT, "app"), quiet=1, force=True)
    ok = compileall.compile_dir(os.path.join(ROOT, "tests"), quiet=1, force=True) and ok
    try:
        import app.examples  # noqa: F401
        import app.recovery  # noqa: F401
        import app.sector  # noqa: F401
        import app.server  # noqa: F401
        import app.storage  # noqa: F401
    except Exception as exc:  # pragma: no cover
        return False, f"import failed: {exc}"
    return (True, "") if ok else (False, "compileall failed")


def step_unit_tests():
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(ROOT, "tests"), top_level_dir=ROOT)
    runner = unittest.TextTestRunner(verbosity=1, stream=sys.stdout)
    return runner.run(suite).wasSuccessful()


def _http(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, {"error": body}


def _wait_health(base, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, body = _http("GET", base + "/health")
            if status == 200 and body.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def step_http_smoke(base):
    from app.examples import build_scenario

    ok_all = True
    if not _wait_health(base):
        report("http.health", False, "health endpoint not ready")
        return False
    report("http.health", True)

    expectations = {
        "complete": {"slot": "B", "generation": 7, "violation": None},
        "corrupt-complete": {"slot": "B", "generation": 3, "violation": "checksum"},
        "retain-old": {"slot": "A", "generation": 5, "violation": "truncation"},
    }
    for name, expect in expectations.items():
        scenario = build_scenario(name)
        audit_id = f"verify-{name}-{uuid.uuid4().hex[:8]}"
        payload = {
            "audit_id": audit_id,
            "initial_slot": scenario["initial_slot"],
            "sectors": scenario["sectors"],
        }
        status, doc = _http("POST", base + "/api/audits", payload)
        ok = status == 201
        if ok:
            concl = doc.get("conclusion", {})
            viol = doc.get("first_violation")
            ok = (
                concl.get("source") == "committed"
                and concl.get("slot") == expect["slot"]
                and concl.get("generation") == expect["generation"]
            )
            if expect["violation"] is None:
                ok = ok and viol is None
            else:
                ok = ok and viol is not None and viol.get("kind") == expect["violation"]
        report(
            f"http.scenario.{name}",
            ok,
            f"status={status} body={json.dumps(doc, ensure_ascii=False)[:400]}" if not ok else "",
        )
        ok_all = ok_all and ok
        if not ok:
            continue

        # frozen conclusion must be re-viewable and identical
        status2, doc2 = _http("GET", f"{base}/api/audits/{audit_id}")
        ok = status2 == 200 and doc2.get("conclusion") == doc.get("conclusion")
        report(f"http.frozen.{name}", ok, f"status={status2}" if not ok else "")
        ok_all = ok_all and ok

        # re-submitting the same audit id must be rejected (conclusion frozen)
        status3, _ = _http("POST", base + "/api/audits", payload)
        ok = status3 == 409
        report(f"http.duplicate.{name}", ok, f"status={status3}" if not ok else "")
        ok_all = ok_all and ok
    return ok_all


def main():
    base = os.environ.get("APP_URL", "http://127.0.0.1:8000").rstrip("/")

    print("== verify: build check ==", flush=True)
    ok, detail = step_build_check()
    report("build.compile-and-import", ok, detail)
    build_ok = ok

    print("== verify: unit tests ==", flush=True)
    tests_ok = step_unit_tests()
    report("unit.tests", tests_ok)

    print(f"== verify: HTTP smoke against {base} ==", flush=True)
    smoke_ok = step_http_smoke(base)

    all_ok = build_ok and tests_ok and smoke_ok
    print(
        f"== verify: {'ALL CHECKS PASSED' if all_ok else 'FAILURES PRESENT'} ==",
        flush=True,
    )
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
