"""Deterministic example sector logs shared by the page and the smoke tests."""
from __future__ import annotations

from .sector import (
    build_complete,
    build_prepare,
    build_slot_page,
    digest_of,
    to_b64,
)

SCENARIOS = ("complete", "corrupt-complete", "retain-old")


def _tx(slot, txid, generation, content):
    d = digest_of(content)
    return [
        to_b64(build_prepare(slot, txid, generation, d)),
        to_b64(build_slot_page(slot, txid, generation, content)),
        to_b64(build_complete(slot, txid, generation, d)),
    ]


def build_scenario(name):
    if name == "complete":
        return {
            "initial_slot": "A",
            "sectors": _tx("B", 0x1001, 7, b"BOOT=LINUX;REV=7;FLAGS=SAFE"),
            "note": "完整事务：准备记录 → 槽页 → 完成记录，重启应切换到槽 B 第 7 代",
        }
    if name == "corrupt-complete":
        sectors = _tx("B", 0x2001, 3, b"BOOT=LINUX;REV=3")
        content = b"BOOT=LINUX;REV=4"
        d = digest_of(content)
        sectors.append(to_b64(build_prepare("A", 0x2002, 4, d)))
        sectors.append(to_b64(build_slot_page("A", 0x2002, 4, content)))
        bad = bytearray(build_complete("A", 0x2002, 4, d))
        bad[63] ^= 0xFF  # corrupt the sector CRC of the complete marker
        sectors.append(to_b64(bytes(bad)))
        return {
            "initial_slot": "A",
            "sectors": sectors,
            "note": "第 4 代的完成标记 CRC 损坏：首个违约被定位，结论保留槽 B 第 3 代",
        }
    if name == "retain-old":
        sectors = _tx("A", 0x3001, 5, b"BOOT=RTOS;REV=5")
        content = b"BOOT=RTOS;REV=6"
        d = digest_of(content)
        sectors.append(to_b64(build_prepare("B", 0x3002, 6, d)))
        sectors.append(to_b64(build_slot_page("B", 0x3002, 6, content)))
        sectors.append(to_b64(b"SPSE" + b"\x03\x01"))  # truncated write, power cut
        return {
            "initial_slot": "A",
            "sectors": sectors,
            "note": "第 6 代缺少完成记录且后续写入被截断：旧有效槽 A 第 5 代保留",
        }
    raise KeyError(name)
