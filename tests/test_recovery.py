import base64
import unittest

from app.recovery import evaluate
from app.sector import (
    build_complete,
    build_prepare,
    build_slot_page,
    digest_of,
    to_b64,
)


def tx_sectors(slot, txid, generation, content):
    d = digest_of(content)
    return [
        to_b64(build_prepare(slot, txid, generation, d)),
        to_b64(build_slot_page(slot, txid, generation, content)),
        to_b64(build_complete(slot, txid, generation, d)),
    ]


def corrupt_crc(b64):
    raw = bytearray(base64.b64decode(b64))
    raw[63] ^= 0xFF
    return to_b64(bytes(raw))


class RecoveryTests(unittest.TestCase):
    # -- mandated scenario: 完整切换 -------------------------------------
    def test_complete_switch(self):
        sectors = tx_sectors("B", 11, 7, b"PARAMS-V7")
        res = evaluate("A", sectors)
        self.assertIsNone(res["first_violation"])
        concl = res["conclusion"]
        self.assertEqual(concl["source"], "committed")
        self.assertEqual(concl["slot"], "B")
        self.assertEqual(concl["generation"], 7)
        self.assertEqual(concl["txid"], 11)
        self.assertEqual(concl["payload_digest"], f"{digest_of(b'PARAMS-V7'):08x}")
        self.assertTrue(all(r["decision"] == "adopted" for r in res["records"]))
        self.assertTrue(all(r["basis"] for r in res["records"]))

    # -- mandated scenario: 完成标记损坏 ----------------------------------
    def test_corrupt_complete_marker(self):
        sectors = tx_sectors("B", 11, 3, b"GEN3")
        sectors += [
            to_b64(build_prepare("A", 12, 4, digest_of(b"GEN4"))),
            to_b64(build_slot_page("A", 12, 4, b"GEN4")),
        ]
        sectors.append(corrupt_crc(to_b64(build_complete("A", 12, 4, digest_of(b"GEN4")))))
        res = evaluate("A", sectors)
        viol = res["first_violation"]
        self.assertIsNotNone(viol)
        self.assertEqual(viol["kind"], "checksum")
        self.assertEqual(viol["index"], 5)
        # the half-written newer generation must not be reported bootable
        self.assertEqual(res["conclusion"]["slot"], "B")
        self.assertEqual(res["conclusion"]["generation"], 3)

    # -- mandated scenario: 旧有效槽保留 ----------------------------------
    def test_retain_old_valid_slot(self):
        sectors = tx_sectors("A", 21, 5, b"OLD-GEN5")
        sectors += [
            to_b64(build_prepare("B", 22, 6, digest_of(b"NEW-GEN6"))),
            to_b64(build_slot_page("B", 22, 6, b"NEW-GEN6")),
            # power cut: no complete record for generation 6
        ]
        res = evaluate("A", sectors)
        self.assertIsNone(res["first_violation"])
        self.assertEqual(res["conclusion"]["slot"], "A")
        self.assertEqual(res["conclusion"]["generation"], 5)
        self.assertEqual(res["conclusion"]["payload_digest"], f"{digest_of(b'OLD-GEN5'):08x}")

    def test_invalid_writes_after_violation_do_not_override(self):
        sectors = tx_sectors("A", 21, 5, b"OLD-GEN5")
        sectors.append(to_b64(b"SPSE\x03"))  # truncated write
        sectors += tx_sectors("B", 22, 9, b"GEN9")  # would-be newer commit
        res = evaluate("A", sectors)
        self.assertEqual(res["first_violation"]["kind"], "truncation")
        self.assertEqual(res["first_violation"]["index"], 3)
        self.assertEqual(res["conclusion"]["slot"], "A")
        self.assertEqual(res["conclusion"]["generation"], 5)
        self.assertEqual(
            [r["decision"] for r in res["records"][4:]], ["unevaluated"] * 3
        )

    # -- violation kinds ---------------------------------------------------
    def test_truncated_sector(self):
        res = evaluate("A", [to_b64(b"SPSE")])
        self.assertEqual(res["first_violation"]["kind"], "truncation")
        self.assertEqual(res["conclusion"]["source"], "initial")
        self.assertEqual(res["conclusion"]["slot"], "A")

    def test_payload_checksum_error(self):
        raw = bytearray(build_slot_page("B", 31, 4, b"X"))
        raw[20] ^= 0x01  # flip a payload bit, then fix the sector CRC
        import struct

        from app.sector import crc32

        raw[60:64] = struct.pack("<I", crc32(bytes(raw[0:60])))
        res = evaluate("A", [to_b64(bytes(raw))])
        self.assertEqual(res["first_violation"]["kind"], "checksum")

    def test_duplicate_txid_inconsistent(self):
        sectors = [
            to_b64(build_prepare("B", 41, 4, digest_of(b"X"))),
            to_b64(build_prepare("B", 41, 4, digest_of(b"Y"))),
        ]
        res = evaluate("A", sectors)
        self.assertEqual(res["first_violation"]["kind"], "duplicate_txid")
        self.assertEqual(res["first_violation"]["index"], 1)

    def test_complete_pointing_to_unfinished_page(self):
        sectors = [
            to_b64(build_prepare("B", 51, 4, digest_of(b"X"))),
            to_b64(build_complete("B", 51, 4, digest_of(b"X"))),
        ]
        res = evaluate("A", sectors)
        self.assertEqual(res["first_violation"]["kind"], "unfinished_page")
        self.assertEqual(res["conclusion"]["source"], "initial")

    def test_page_before_prepare_is_order_violation(self):
        sectors = [to_b64(build_slot_page("B", 61, 4, b"X"))]
        res = evaluate("A", sectors)
        self.assertEqual(res["first_violation"]["kind"], "order")

    def test_page_digest_mismatch(self):
        sectors = [
            to_b64(build_prepare("B", 71, 4, digest_of(b"EXPECTED"))),
            to_b64(build_slot_page("B", 71, 4, b"OTHER")),
        ]
        res = evaluate("A", sectors)
        self.assertEqual(res["first_violation"]["kind"], "digest_mismatch")

    def test_invalid_base64(self):
        res = evaluate("A", ["!!!not-base64!!!"])
        self.assertEqual(res["first_violation"]["kind"], "encoding")

    # -- selection rules ---------------------------------------------------
    def test_same_generation_tie_chooses_slot_name(self):
        sectors = tx_sectors("B", 81, 8, b"GEN8-B") + tx_sectors("A", 82, 8, b"GEN8-A")
        res = evaluate("A", sectors)
        self.assertEqual(res["conclusion"]["generation"], 8)
        self.assertEqual(res["conclusion"]["slot"], "A")

    def test_lower_generation_commit_does_not_override(self):
        sectors = tx_sectors("B", 91, 9, b"GEN9") + tx_sectors("A", 92, 4, b"GEN4")
        res = evaluate("A", sectors)
        self.assertEqual(res["conclusion"]["generation"], 9)
        self.assertEqual(res["conclusion"]["slot"], "B")

    def test_no_valid_transaction_keeps_initial(self):
        res = evaluate("B", [to_b64(build_prepare("A", 95, 1, digest_of(b"X")))])
        self.assertEqual(res["conclusion"]["source"], "initial")
        self.assertEqual(res["conclusion"]["slot"], "B")

    def test_superseded_prepare_is_discarded_not_violation(self):
        sectors = [to_b64(build_prepare("B", 96, 1, digest_of(b"X")))]
        sectors += tx_sectors("A", 97, 2, b"Y")
        res = evaluate("A", sectors)
        self.assertIsNone(res["first_violation"])
        self.assertEqual(res["records"][0]["decision"], "discarded")
        self.assertEqual(res["conclusion"]["slot"], "A")
        self.assertEqual(res["conclusion"]["generation"], 2)


if __name__ == "__main__":
    unittest.main()
