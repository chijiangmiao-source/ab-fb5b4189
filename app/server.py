"""HTTP API and page server for the slot-switch recovery auditor.

Routes:
    GET  /                     audit page (driven by the JSON API)
    GET  /health               health check
    GET  /api/example?scenario=complete|corrupt-complete|retain-old
    POST /api/audits           submit an audit; the conclusion is frozen
    GET  /api/audits/<id>      re-view a frozen conclusion by audit id
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .examples import SCENARIOS, build_scenario
from .recovery import evaluate
from .sector import MAX_SECTORS
from .storage import AuditStore

AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
INDEX_HTML = Path(__file__).with_name("static") / "index.html"


def _validate(data):
    if not isinstance(data, dict):
        return "请求体必须是 JSON 对象"
    audit_id = data.get("audit_id")
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.match(audit_id):
        return "审计标识必须是 1-64 位、以字母或数字开头、可含 . _ - 的字符串"
    if data.get("initial_slot") not in ("A", "B"):
        return "初始活动槽必须是 A 或 B"
    sectors = data.get("sectors")
    if not isinstance(sectors, list) or not sectors:
        return "扇区列表不能为空"
    if len(sectors) > MAX_SECTORS:
        return f"扇区数量 {len(sectors)} 超过上限 {MAX_SECTORS}"
    if any(not isinstance(s, str) or not s.strip() for s in sectors):
        return "每个扇区必须是非空的 Base64 字符串"
    return None


def make_server(host, port, db_path):
    store = AuditStore(db_path)

    class Handler(BaseHTTPRequestHandler):
        server_version = "SlotAudit/1.0"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # keep container logs clean
            pass

        def _send(self, status, body, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status, obj):
            self._send(
                status,
                json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/health":
                self._send_json(200, {"status": "ok"})
            elif path in ("/", "/index.html"):
                self._send(
                    200,
                    INDEX_HTML.read_text(encoding="utf-8").encode("utf-8"),
                    "text/html; charset=utf-8",
                )
            elif path == "/api/example":
                name = parse_qs(parsed.query).get("scenario", ["complete"])[0]
                try:
                    self._send_json(200, build_scenario(name))
                except KeyError:
                    self._send_json(
                        404,
                        {"error": f"未知示例场景 {name!r}，可选：{', '.join(SCENARIOS)}"},
                    )
            elif path.startswith("/api/audits/"):
                audit_id = unquote(path[len("/api/audits/"):])
                doc = store.get(audit_id)
                if doc is None:
                    self._send_json(404, {"error": f"审计标识 {audit_id!r} 不存在"})
                else:
                    self._send_json(200, doc)
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path != "/api/audits":
                self._send_json(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > 1_000_000:
                self._send_json(400, {"error": "请求体缺失或过大"})
                return
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._send_json(400, {"error": "请求体不是有效 JSON"})
                return
            error = _validate(data)
            if error:
                self._send_json(400, {"error": error})
                return
            audit_id = data["audit_id"]
            result = evaluate(
                data["initial_slot"], [s.strip() for s in data["sectors"]]
            )
            created_at = datetime.now(timezone.utc).isoformat()
            doc = {"audit_id": audit_id, "created_at": created_at, **result}
            if not store.create(audit_id, doc, created_at):
                self._send_json(
                    409,
                    {
                        "error": f"审计标识 {audit_id!r} 已存在，恢复结论已冻结，"
                        f"请通过 GET /api/audits/{audit_id} 查看"
                    },
                )
                return
            self._send_json(201, doc)

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.store = store
    return httpd


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    data_dir = os.environ.get("DATA_DIR", "./data")
    db_path = os.path.join(data_dir, "audits.db")
    httpd = make_server(host, port, db_path)
    print(f"slot-audit listening on {host}:{port}, db={db_path}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
