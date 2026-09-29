import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app.sector import build_complete, build_prepare, build_slot_page, digest_of, to_b64
from app.server import make_server


def http(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.httpd = make_server("127.0.0.1", 0, f"{cls.tmp.name}/t.db")
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def _sectors(self):
        d = digest_of(b"P1")
        return [
            to_b64(build_prepare("B", 1, 1, d)),
            to_b64(build_slot_page("B", 1, 1, b"P1")),
            to_b64(build_complete("B", 1, 1, d)),
        ]

    def test_health(self):
        status, body = http("GET", self.base + "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_create_and_get_frozen(self):
        status, doc = http(
            "POST",
            self.base + "/api/audits",
            {"audit_id": "t-create", "initial_slot": "A", "sectors": self._sectors()},
        )
        self.assertEqual(status, 201)
        self.assertEqual(doc["conclusion"]["slot"], "B")
        self.assertEqual(doc["conclusion"]["generation"], 1)
        self.assertEqual(len(doc["records"]), 3)

        status, doc2 = http("GET", self.base + "/api/audits/t-create")
        self.assertEqual(status, 200)
        self.assertEqual(doc2["conclusion"], doc["conclusion"])
        self.assertEqual(doc2["created_at"], doc["created_at"])

        # the frozen conclusion must not be overwritten by a re-submission
        status, _ = http(
            "POST",
            self.base + "/api/audits",
            {"audit_id": "t-create", "initial_slot": "A", "sectors": self._sectors()},
        )
        self.assertEqual(status, 409)

    def test_get_missing(self):
        status, _ = http("GET", self.base + "/api/audits/nope")
        self.assertEqual(status, 404)

    def test_validation(self):
        # more than 32 sectors
        status, _ = http(
            "POST",
            self.base + "/api/audits",
            {"audit_id": "t-many", "initial_slot": "A", "sectors": ["QQ=="] * 33},
        )
        self.assertEqual(status, 400)
        # exactly 32 sectors is accepted
        status, doc = http(
            "POST",
            self.base + "/api/audits",
            {"audit_id": "t-32", "initial_slot": "A", "sectors": ["QQ=="] * 32},
        )
        self.assertEqual(status, 201)
        self.assertEqual(doc["sector_count"], 32)
        # bad initial slot
        status, _ = http(
            "POST",
            self.base + "/api/audits",
            {"audit_id": "t-slot", "initial_slot": "C", "sectors": ["QQ=="]},
        )
        self.assertEqual(status, 400)
        # bad audit id
        status, _ = http(
            "POST",
            self.base + "/api/audits",
            {"audit_id": "bad id!", "initial_slot": "A", "sectors": ["QQ=="]},
        )
        self.assertEqual(status, 400)
        # empty sector list
        status, _ = http(
            "POST",
            self.base + "/api/audits",
            {"audit_id": "t-empty", "initial_slot": "A", "sectors": []},
        )
        self.assertEqual(status, 400)

    def test_example_endpoint(self):
        for name in ("complete", "corrupt-complete", "retain-old"):
            status, body = http("GET", self.base + f"/api/example?scenario={name}")
            self.assertEqual(status, 200)
            self.assertTrue(body["sectors"])
        status, _ = http("GET", self.base + "/api/example?scenario=nope")
        self.assertEqual(status, 404)

    def test_index_page(self):
        with urllib.request.urlopen(self.base + "/", timeout=5) as resp:
            html = resp.read().decode()
        self.assertIn("审计", html)


if __name__ == "__main__":
    unittest.main()
