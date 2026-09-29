"""Fixed-length sector format for boot-parameter slot-switch audits.

Layout (64 bytes, little-endian)::

    offset  size  field
    0       4     magic b"SPSE"
    4       1     record type: 1=slot page, 2=prepare, 3=complete
    5       1     slot id: 0='A', 1='B'
    6       2     reserved (zero)
    8       4     transaction id (uint32)
    12      4     generation (uint32)
    16      4     payload length (uint32, 0..32)
    20      32    payload (zero padded)
    52      4     payload CRC32 (CRC32 of the payload bytes)
    56      4     reserved (zero)
    60      4     sector CRC32 (CRC32 of bytes 0..59)

Prepare and complete records carry, as their 4-byte payload, the CRC32
digest of the slot-page payload their transaction refers to.
"""
from __future__ import annotations

import base64
import binascii
import struct
from dataclasses import dataclass

SECTOR_SIZE = 64
MAGIC = b"SPSE"
MAX_PAYLOAD = 32
MAX_SECTORS = 32

TYPE_SLOT_PAGE = 0x01
TYPE_PREPARE = 0x02
TYPE_COMPLETE = 0x03
TYPE_NAMES = {
    TYPE_SLOT_PAGE: "slot_page",
    TYPE_PREPARE: "prepare",
    TYPE_COMPLETE: "complete",
}

SLOT_IDS = {"A": 0x00, "B": 0x01}
SLOT_NAMES = {v: k for k, v in SLOT_IDS.items()}


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


class SectorViolation(Exception):
    """A raw sector failed byte-level parsing or an integrity check."""

    def __init__(self, detail: str, kind: str = "structural"):
        super().__init__(detail)
        self.detail = detail
        self.kind = kind


@dataclass
class Sector:
    type: int
    slot: str
    txid: int
    generation: int
    payload: bytes
    payload_crc: int
    raw: bytes

    @property
    def type_name(self) -> str:
        return TYPE_NAMES[self.type]

    @property
    def expected_digest(self) -> int:
        """Digest of the referenced slot-page payload (prepare/complete)."""
        return struct.unpack("<I", self.payload[:4])[0]

    @property
    def digest_ref(self) -> int:
        if self.type == TYPE_SLOT_PAGE:
            return self.payload_crc
        return self.expected_digest


def parse_sector(raw: bytes) -> Sector:
    """Parse one fixed-length sector, raising SectorViolation on the first
    integrity or structural defect found while scanning byte by byte."""
    if len(raw) != SECTOR_SIZE:
        raise SectorViolation(
            f"扇区长度为 {len(raw)} 字节，不是定长 {SECTOR_SIZE} 字节（截断或超长）",
            kind="truncation",
        )
    if raw[0:4] != MAGIC:
        raise SectorViolation(f"魔数 {raw[0:4].hex()} 与 SPSE 不符", kind="structural")
    stored_crc = struct.unpack("<I", raw[60:64])[0]
    actual_crc = crc32(raw[0:60])
    if stored_crc != actual_crc:
        raise SectorViolation(
            f"扇区 CRC32 校验失败（记录值 {stored_crc:08x}，计算值 {actual_crc:08x}）",
            kind="checksum",
        )
    rectype = raw[4]
    if rectype not in TYPE_NAMES:
        raise SectorViolation(
            f"未知记录类型 0x{rectype:02x}（扇区只允许表示槽页、准备记录或完成记录）",
            kind="structural",
        )
    slot_byte = raw[5]
    if slot_byte not in SLOT_NAMES:
        raise SectorViolation(f"未知槽编号 0x{slot_byte:02x}", kind="structural")
    if raw[6:8] != b"\x00\x00":
        raise SectorViolation("保留字节 6-7 非零", kind="structural")
    txid, generation, payload_len = struct.unpack("<III", raw[8:20])
    if payload_len > MAX_PAYLOAD:
        raise SectorViolation(
            f"载荷长度 {payload_len} 超过上限 {MAX_PAYLOAD}", kind="structural"
        )
    payload = raw[20 : 20 + payload_len]
    if raw[20 + payload_len : 52] != b"\x00" * (MAX_PAYLOAD - payload_len):
        raise SectorViolation("载荷填充区非零", kind="structural")
    payload_crc = struct.unpack("<I", raw[52:56])[0]
    if crc32(payload) != payload_crc:
        raise SectorViolation(
            f"载荷 CRC32 校验失败（记录值 {payload_crc:08x}，计算值 {crc32(payload):08x}）",
            kind="checksum",
        )
    if raw[56:60] != b"\x00\x00\x00\x00":
        raise SectorViolation("保留字节 56-59 非零", kind="structural")
    if rectype in (TYPE_PREPARE, TYPE_COMPLETE) and payload_len != 4:
        raise SectorViolation(
            "准备/完成记录的载荷必须是 4 字节目标页摘要", kind="structural"
        )
    return Sector(rectype, SLOT_NAMES[slot_byte], txid, generation, payload, payload_crc, raw)


def build_sector(rectype: int, slot: str, txid: int, generation: int, payload: bytes = b"") -> bytes:
    if rectype not in TYPE_NAMES:
        raise ValueError("unknown record type")
    if slot not in SLOT_IDS:
        raise ValueError("unknown slot")
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too long")
    body = (
        MAGIC
        + bytes([rectype, SLOT_IDS[slot]])
        + b"\x00\x00"
        + struct.pack("<III", txid, generation, len(payload))
        + payload.ljust(MAX_PAYLOAD, b"\x00")
        + struct.pack("<I", crc32(payload))
        + b"\x00\x00\x00\x00"
    )
    return body + struct.pack("<I", crc32(body))


def build_slot_page(slot: str, txid: int, generation: int, content: bytes) -> bytes:
    return build_sector(TYPE_SLOT_PAGE, slot, txid, generation, content)


def build_prepare(slot: str, txid: int, generation: int, page_digest: int) -> bytes:
    return build_sector(TYPE_PREPARE, slot, txid, generation, struct.pack("<I", page_digest))


def build_complete(slot: str, txid: int, generation: int, page_digest: int) -> bytes:
    return build_sector(TYPE_COMPLETE, slot, txid, generation, struct.pack("<I", page_digest))


def digest_of(content: bytes) -> int:
    return crc32(content)


def to_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")
