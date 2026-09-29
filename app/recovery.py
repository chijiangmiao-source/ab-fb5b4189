"""Sequential replay of the exported sector log.

The auditor replays sectors strictly in physical write order. The active
slot switches only when a prepare record, a fully written target slot page
and a complete record of the *same* transaction are all intact, carry
matching transaction ids and payload digests, and appear in that write
order. The first violation halts the replay, so invalid writes that appear
later can never override the last valid generation.

The adjudicator deliberately does NOT:
  * pick a "latest page number" (generation/slot recency alone),
  * skip or ignore corrupt records, or
  * trust a bare complete flag without the matching prepare and page.
"""
from __future__ import annotations

import base64
import binascii

from .sector import (
    TYPE_COMPLETE,
    TYPE_PREPARE,
    TYPE_SLOT_PAGE,
    SectorViolation,
    parse_sector,
)

DECISION_ADOPTED = "adopted"
DECISION_DISCARDED = "discarded"
DECISION_VIOLATION = "violation"
DECISION_UNEVALUATED = "unevaluated"


class TxViolation(Exception):
    """A structurally intact record breaks transaction-level rules."""

    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


def _fmt_sig(sig) -> str:
    return f"代次 {sig[0]} / 槽 {sig[1]} / 摘要 {sig[2]:08x}"


class _Replay:
    def __init__(self):
        self.records = []
        self.committed = []
        self.committed_sigs = {}
        self.txid_sigs = {}
        self.pending = None

    # -- record bookkeeping ---------------------------------------------
    def _record(self, index, sec, decision, basis, raw=None):
        rec = {"index": index, "decision": decision, "basis": basis}
        if sec is not None:
            rec.update(
                type=sec.type_name,
                slot=sec.slot,
                txid=sec.txid,
                generation=sec.generation,
                digest=f"{sec.digest_ref:08x}",
            )
        else:
            rec.update(type="unknown", slot=None, txid=None, generation=None, digest=None)
            if raw is not None:
                rec["raw_prefix_hex"] = raw[:16].hex()
        self.records.append(rec)
        return rec

    def _supersede_pending(self, new_index):
        p = self.pending
        self.records[p["prepare_index"]]["decision"] = DECISION_DISCARDED
        self.records[p["prepare_index"]]["basis"] += (
            f"；事务未完成，被 #{new_index} 处新的准备记录取代"
        )
        if p["page_index"] is not None:
            self.records[p["page_index"]]["decision"] = DECISION_DISCARDED
            self.records[p["page_index"]]["basis"] += (
                f"；所属事务被 #{new_index} 处的准备记录取代，未提交"
            )
        self.pending = None

    # -- record application ----------------------------------------------
    def apply(self, sec, index):
        if sec.type == TYPE_PREPARE:
            decision, basis = self._apply_prepare(sec, index)
        elif sec.type == TYPE_SLOT_PAGE:
            decision, basis = self._apply_page(sec, index)
        else:
            decision, basis = self._apply_complete(sec, index)
        self._record(index, sec, decision, basis)

    def _apply_prepare(self, sec, index):
        sig = (sec.generation, sec.slot, sec.expected_digest)
        known = self.txid_sigs.get(sec.txid)
        if known is not None and known != sig:
            raise TxViolation(
                "duplicate_txid",
                f"事务标识 {sec.txid} 的准备记录与先前接受的内容不一致"
                f"（先前：{_fmt_sig(known)}；当前：{_fmt_sig(sig)}）",
            )
        if sec.txid in self.committed_sigs:
            return DECISION_DISCARDED, f"事务 {sec.txid} 已提交，内容一致的冗余准备记录，舍弃"
        if self.pending is not None and self.pending["txid"] != sec.txid:
            self._supersede_pending(index)
        if self.pending is not None:
            return (
                DECISION_DISCARDED,
                f"与 #{self.pending['prepare_index']} 的准备记录内容一致，冗余重复，舍弃",
            )
        self.pending = {
            "txid": sec.txid,
            "generation": sec.generation,
            "slot": sec.slot,
            "digest": sec.expected_digest,
            "prepare_index": index,
            "page_index": None,
            "content": None,
        }
        self.txid_sigs[sec.txid] = sig
        return (
            DECISION_ADOPTED,
            f"准备记录完整，开启事务 {sec.txid}（目标槽 {sec.slot}，第 {sec.generation} 代，"
            f"期望页摘要 {sec.expected_digest:08x}）",
        )

    def _apply_page(self, sec, index):
        sig = (sec.generation, sec.slot, sec.payload_crc)
        p = self.pending
        if p is None or p["txid"] != sec.txid:
            known = self.txid_sigs.get(sec.txid)
            if known is not None and known != sig:
                raise TxViolation(
                    "duplicate_txid",
                    f"事务标识 {sec.txid} 的槽页与先前接受的内容不一致"
                    f"（先前：{_fmt_sig(known)}；当前：{_fmt_sig(sig)}）",
                )
            if sec.txid in self.committed_sigs:
                return DECISION_DISCARDED, f"事务 {sec.txid} 已提交，内容一致的冗余槽页，舍弃"
            if p is None:
                raise TxViolation(
                    "order", f"槽页（事务 {sec.txid}）之前没有任何准备记录，写入顺序错误"
                )
            raise TxViolation(
                "order",
                f"槽页（事务 {sec.txid}）与当前待决事务 {p['txid']} 的准备记录不符，写入顺序错误",
            )
        if sec.generation != p["generation"] or sec.slot != p["slot"]:
            raise TxViolation(
                "digest_mismatch",
                f"槽页事务参数（代次 {sec.generation}，槽 {sec.slot}）与准备记录"
                f"（代次 {p['generation']}，槽 {p['slot']}）不符",
            )
        if sec.payload_crc != p["digest"]:
            raise TxViolation(
                "digest_mismatch",
                f"槽页载荷摘要 {sec.payload_crc:08x} 与准备记录声明的摘要 {p['digest']:08x} 不符",
            )
        if p["page_index"] is not None:
            return DECISION_DISCARDED, f"与 #{p['page_index']} 的槽页内容一致，冗余重复，舍弃"
        p["page_index"] = index
        p["content"] = sec.payload
        return (
            DECISION_ADOPTED,
            f"目标槽 {sec.slot} 的槽页完整，载荷摘要 {sec.payload_crc:08x} 与准备记录相符",
        )

    def _apply_complete(self, sec, index):
        sig = (sec.generation, sec.slot, sec.expected_digest)
        if sec.txid in self.committed_sigs:
            if self.committed_sigs[sec.txid] != sig:
                raise TxViolation(
                    "duplicate_txid",
                    f"事务标识 {sec.txid} 的完成记录与已提交内容不一致"
                    f"（已提交：{_fmt_sig(self.committed_sigs[sec.txid])}；当前：{_fmt_sig(sig)}）",
                )
            return DECISION_DISCARDED, f"事务 {sec.txid} 已提交，内容一致的冗余完成记录，舍弃"
        p = self.pending
        if p is None or p["txid"] != sec.txid:
            known = self.txid_sigs.get(sec.txid)
            if known is not None and known != sig:
                raise TxViolation(
                    "duplicate_txid",
                    f"事务标识 {sec.txid} 的完成记录与先前接受的内容不一致"
                    f"（先前：{_fmt_sig(known)}；当前：{_fmt_sig(sig)}）",
                )
            raise TxViolation(
                "unfinished_page",
                f"完成记录指向事务 {sec.txid}，但不存在匹配的待决准备记录，目标槽页未完成",
            )
        if p["page_index"] is None:
            raise TxViolation(
                "unfinished_page",
                f"完成记录指向事务 {sec.txid}，但其目标槽 {p['slot']} 的槽页尚未完整写入",
            )
        expected = (p["generation"], p["slot"], p["digest"])
        if sig != expected:
            raise TxViolation(
                "digest_mismatch",
                f"完成记录（{_fmt_sig(sig)}）与槽页（{_fmt_sig(expected)}）的事务参数或摘要不同",
            )
        self.committed.append(
            {
                "generation": p["generation"],
                "slot": p["slot"],
                "txid": sec.txid,
                "digest": p["digest"],
                "content": p["content"],
                "index": index,
            }
        )
        self.committed_sigs[sec.txid] = sig
        self.pending = None
        return (
            DECISION_ADOPTED,
            f"完成记录与槽页相符，事务 {sec.txid} 提交：槽 {p['slot']} 第 {p['generation']} 代成为恢复候选",
        )


def _select(committed):
    # Highest generation wins; ties are broken by physical slot name, then by
    # earliest commit order, so the choice is stable and deterministic.
    return min(committed, key=lambda c: (-c["generation"], c["slot"], c["index"]))


def evaluate(initial_slot, sectors_b64):
    """Replay the sector log and return the frozen recovery conclusion."""
    replay = _Replay()
    first_violation = None

    for i, token in enumerate(sectors_b64):
        try:
            raw = base64.b64decode(token.strip(), validate=True)
        except (binascii.Error, ValueError):
            first_violation = {
                "index": i,
                "kind": "encoding",
                "detail": "扇区不是有效的 Base64 编码",
            }
            replay._record(i, None, DECISION_VIOLATION, first_violation["detail"])
            break
        try:
            sec = parse_sector(raw)
        except SectorViolation as exc:
            first_violation = {"index": i, "kind": exc.kind, "detail": exc.detail}
            replay._record(i, None, DECISION_VIOLATION, exc.detail, raw=raw)
            break
        try:
            replay.apply(sec, i)
        except TxViolation as exc:
            first_violation = {"index": i, "kind": exc.kind, "detail": exc.detail}
            replay._record(i, sec, DECISION_VIOLATION, exc.detail)
            break

    if first_violation is not None:
        for j in range(len(replay.records), len(sectors_b64)):
            replay.records.append(
                {
                    "index": j,
                    "type": None,
                    "slot": None,
                    "txid": None,
                    "generation": None,
                    "digest": None,
                    "decision": DECISION_UNEVALUATED,
                    "basis": (
                        f"重放在扇区 #{first_violation['index']} 的首个违约处停止，"
                        "该记录未被评估，不得覆盖已保留的有效代次"
                    ),
                }
            )

    if replay.committed:
        best = _select(replay.committed)
        ties = [c for c in replay.committed if c["generation"] == best["generation"]]
        basis = (
            f"第 {best['generation']} 代是镜像中完整提交的最高有效代次"
            f"（事务 {best['txid']}，于扇区 #{best['index']} 提交）"
        )
        if len(ties) > 1:
            basis += f"；相同代次存在 {len(ties)} 个提交，按物理槽名稳定选择槽 {best['slot']}"
        conclusion = {
            "source": "committed",
            "slot": best["slot"],
            "generation": best["generation"],
            "txid": best["txid"],
            "payload_digest": f"{best['digest']:08x}",
            "payload_base64": base64.b64encode(best["content"]).decode("ascii"),
            "payload_hex": best["content"].hex(),
            "committed_at_index": best["index"],
            "basis": basis,
        }
    else:
        conclusion = {
            "source": "initial",
            "slot": initial_slot,
            "generation": None,
            "txid": None,
            "payload_digest": None,
            "payload_base64": None,
            "payload_hex": None,
            "committed_at_index": None,
            "basis": (
                f"镜像中不存在完整提交的事务，重启将保持初始活动槽 {initial_slot}"
                "（其内容未包含在导出镜像中）"
            ),
        }

    return {
        "initial_slot": initial_slot,
        "sector_count": len(sectors_b64),
        "evaluated_count": sum(
            1 for r in replay.records if r["decision"] != DECISION_UNEVALUATED
        ),
        "halted": first_violation is not None,
        "first_violation": first_violation,
        "records": replay.records,
        "conclusion": conclusion,
    }
