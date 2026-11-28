"""Durability oracle and on-flash FCB parser for Zephyr FCB and settings-on-FCB.

Validates the five durability requirements after every recovery boot:
  1. Every record acknowledged before the cut is present at mount with its
     acknowledged sequence number and value.
  2. No key deleted and acknowledged before the cut reappears (either at mount
     or after post-recovery writes).
  3. No record value is torn (at mount or after post-recovery writes).
  4. Operations in flight at the cut are either cleanly applied or cleanly
     absent at mount.
  5. The store still accepts new writes on the recovery boot and converges to
     the expected post-workload key state.
"""

from __future__ import annotations

import re
import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple

from fault_inject import FaultResult
from fault_types import operation_kind_for_fault_type
from invariants import InvariantViolation

FCB_VERDICT_SRAM_BASE = 0x2003F000
FCB_VERDICT_MAGIC_RAW = 0x4643424F
FCB_VERDICT_MAGIC_SETTINGS = 0x53464342
FCB_NUM_TRACKED_KEYS = 7
FCB_EXPECTED_POST_MASK = 0x0000005B

FCB_RAW_MAGIC = 0x46434231
SETTINGS_FCB_MAGIC = 0xC0FFEEEE
FCB_REC_MAGIC_BASE = 0x46437000
FCB_REC_MAGIC_MASK = 0xFFFFFF00
FCB_REC_FLAG_MASK = 0x000000FF
FCB_REC_FLAG_LIVE = 0x00
FCB_REC_FLAG_DELETED = 0x01
FCB_REC_FLAG_FILLER = 0x02
FCB_KEY_FILLER = 0xFE

VERDICT_WORD_NAMES: Tuple[str, ...] = (
    "magic",
    "oracle_ok",
    "mount_ok",
    "mount_oracle_ok",
    "write_ok",
    "post_oracle_ok",
    "mount_present_mask",
    "mount_torn_count",
    "mount_seq_0",
    "mount_seq_1",
    "mount_seq_2",
    "mount_seq_3",
    "mount_seq_4",
    "mount_seq_5",
    "mount_seq_6",
    "post_present_mask",
    "post_torn_count",
    "post_seq_0",
    "post_seq_1",
    "post_seq_2",
    "post_seq_3",
    "post_seq_4",
    "post_seq_5",
    "post_seq_6",
    "last_ack_seq",
    "ack_count",
    "write_err",
)


def crc8_ccitt(init: int, data: bytes) -> int:
    crc = init & 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def align_up(n: int, align: int) -> int:
    if align <= 1:
        return n
    return (n + align - 1) & ~(align - 1)


def expected_val0(key_id: int, seq: int) -> int:
    return (
        (0xA5000000 | ((key_id & 0xFF) << 16) | (seq & 0xFFFF))
        ^ (seq * 0x01010101)
    ) & 0xFFFFFFFF


def expected_val1(key_id: int, seq: int) -> int:
    return (
        (0x5A000000 | ((key_id & 0xFF) << 16) | ((seq * 17) & 0xFFFF))
        ^ 0xC0FFEE11
    ) & 0xFFFFFFFF


def decode_verdict_from_signals(
    result: FaultResult,
    result_signals: Optional[Dict[str, Any]] = None,
    result_dict: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Extract the 27-word SRAM durability verdict block from result signals."""
    if isinstance(result.nvm_state, dict) and "mount_seq" in result.nvm_state:
        return dict(result.nvm_state)

    signals = result_signals if isinstance(result_signals, dict) else {}
    if not signals and isinstance(result_dict, dict):
        raw_sig = result_dict.get("signals")
        if isinstance(raw_sig, dict):
            signals = raw_sig

    if isinstance(signals.get("fcb_oracle_verdict"), dict):
        return dict(signals["fcb_oracle_verdict"])

    word_by_addr: Dict[int, int] = {}
    success_checks = signals.get("success_checks")
    raw_checks: Optional[List[Any]] = None
    if isinstance(success_checks, dict) and isinstance(
        success_checks.get("memory_checks"), list
    ):
        raw_checks = success_checks["memory_checks"]
    elif isinstance(signals.get("memory_checks"), list):
        raw_checks = signals["memory_checks"]

    if raw_checks:
        for entry in raw_checks:
            if not isinstance(entry, dict):
                continue
            raw_addr = entry.get("address")
            raw_actual = entry.get("actual")
            if raw_addr is None or raw_actual is None:
                continue
            try:
                addr = (
                    int(raw_addr, 0)
                    if isinstance(raw_addr, str)
                    else int(raw_addr)
                )
                val = (
                    int(raw_actual, 0)
                    if isinstance(raw_actual, str)
                    else int(raw_actual)
                ) & 0xFFFFFFFF
            except (TypeError, ValueError):
                continue
            word_by_addr[addr] = val

    if not word_by_addr:
        return None

    decoded: Dict[str, Any] = {}
    for index, name in enumerate(VERDICT_WORD_NAMES):
        addr = FCB_VERDICT_SRAM_BASE + (index * 4)
        if addr in word_by_addr:
            decoded[name] = word_by_addr[addr]

    if "magic" not in decoded:
        return None

    decoded["mount_seq"] = [
        int(decoded.get(f"mount_seq_{k}", 0))
        for k in range(FCB_NUM_TRACKED_KEYS)
    ]
    decoded["post_seq"] = [
        int(decoded.get(f"post_seq_{k}", 0))
        for k in range(FCB_NUM_TRACKED_KEYS)
    ]
    return decoded


_ACK_BOUNDARY_RE = re.compile(
    r"^(?:(?P<kind>[A-Za-z_]+)\s*(?:\[\s*(?P<idx1>\d+)\s*\]|:\s*(?P<idx2>\d+)|@\s*(?P<idx3>\d+))"
    r"|(?P<idx4>\d+))$"
)


def parse_ack_boundary(raw_value: Any) -> Optional[Tuple[str, int]]:
    """Parse an integer or kind-qualified point boundary ('w[8]', 'e[0]', 8)."""
    if isinstance(raw_value, bool) or raw_value is None:
        return None
    if isinstance(raw_value, int):
        return ("program", int(raw_value))
    if isinstance(raw_value, str):
        m = _ACK_BOUNDARY_RE.match(raw_value.strip())
        if not m:
            return None
        idx_str = m.group("idx1") or m.group("idx2") or m.group("idx3") or m.group("idx4")
        raw_kind = (m.group("kind") or "w").strip().lower()
        if raw_kind in ("e", "erase", "interrupted_erase"):
            kind = "erase"
        elif raw_kind in ("w", "write", "program", "power_loss"):
            kind = "program"
        else:
            return None
        return (kind, int(idx_str))
    return None


def _resolve_operation_kind(
    fault_type: Optional[str],
    operation_kind: Optional[str] = None,
    *,
    is_control: bool = False,
) -> Optional[str]:
    if is_control:
        return None
    if isinstance(operation_kind, str):
        norm = operation_kind.strip().lower()
        if norm in ("program", "write"):
            return "program"
        if norm in ("erase", "interrupted_erase"):
            return "erase"
    op_kind = operation_kind_for_fault_type(fault_type)
    if op_kind is not None:
        return op_kind
    ft_norm = str(fault_type or "").strip().lower()
    if ft_norm in ("e", "erase", "interrupted_erase"):
        return "erase"
    if ft_norm in ("w", "write", "program", "power_loss"):
        return "program"
    return None


def evaluate_durability_verdict(
    verdict: Dict[str, Any],
    *,
    fault_at: int = -1,
    fault_type: str = "control",
    operation_kind: Optional[str] = None,
    is_control: bool = False,
    ack_write_boundaries: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Evaluate all durability oracle clauses against a decoded SRAM verdict."""
    issues: List[Dict[str, Any]] = []
    resolved_kind = _resolve_operation_kind(
        fault_type, operation_kind, is_control=is_control
    )

    magic = int(verdict.get("magic", 0))
    if magic not in (FCB_VERDICT_MAGIC_RAW, FCB_VERDICT_MAGIC_SETTINGS):
        issues.append(
            {
                "clause": "verdict_magic_present",
                "finding_code": "verdict_magic_invalid",
                "summary": f"unexpected verdict magic 0x{magic:08X}",
                "magic": f"0x{magic:08X}",
            }
        )
        return issues

    mount_ok = int(verdict.get("mount_ok", 0))
    if mount_ok != 1:
        issues.append(
            {
                "clause": "mount_succeeded",
                "finding_code": "recovery_mount_failed",
                "summary": "FCB / settings mount failed on recovery boot",
                "write_err": int(verdict.get("write_err", 0)),
            }
        )

    mount_torn = int(verdict.get("mount_torn_count", 0))
    post_torn = int(verdict.get("post_torn_count", 0))
    if mount_torn != 0 or post_torn != 0:
        issues.append(
            {
                "clause": "no_value_is_torn",
                "finding_code": "torn_record_value",
                "summary": (
                    f"torn record detected (mount_torn_count={mount_torn}, "
                    f"post_torn_count={post_torn})"
                ),
                "mount_torn_count": mount_torn,
                "post_torn_count": post_torn,
            }
        )

    mount_mask = int(verdict.get("mount_present_mask", 0))
    post_mask = int(verdict.get("post_present_mask", 0))
    mount_seq = list(verdict.get("mount_seq") or [0] * FCB_NUM_TRACKED_KEYS)
    post_seq = list(verdict.get("post_seq") or [0] * FCB_NUM_TRACKED_KEYS)

    # 1. Pre-cut acknowledged keys that must always be present at mount.
    lost_keys: List[Dict[str, Any]] = []
    if (mount_mask & (1 << 0)) == 0 or mount_seq[0] != 1:
        lost_keys.append({"key": "k00", "expected_seq": 1, "actual_seq": mount_seq[0]})
    if (mount_mask & (1 << 1)) == 0 or mount_seq[1] != 10:
        lost_keys.append({"key": "k01", "expected_seq": 10, "actual_seq": mount_seq[1]})
    if (mount_mask & (1 << 3)) == 0 or mount_seq[3] not in (4, 24):
        lost_keys.append(
            {"key": "k03", "expected_seq": [4, 24], "actual_seq": mount_seq[3]}
        )
    if (mount_mask & (1 << 4)) == 0 or mount_seq[4] not in (12, 21):
        lost_keys.append(
            {"key": "k04", "expected_seq": [12, 21], "actual_seq": mount_seq[4]}
        )

    # 2. Check cut-specific acknowledged runtime operations when write boundaries are configured.
    ft_norm = str(fault_type or "").strip().lower()
    is_single_write_cut = (
        not is_control
        and fault_at >= 0
        and resolved_kind == "program"
        and ft_norm in ("w", "power_loss")
        and isinstance(ack_write_boundaries, dict)
    )
    parsed_boundaries: Dict[str, int] = {}
    if isinstance(ack_write_boundaries, dict):
        for seq_key, raw_b in ack_write_boundaries.items():
            parsed = parse_ack_boundary(raw_b)
            if parsed is not None and parsed[0] == "program":
                parsed_boundaries[str(seq_key)] = parsed[1]

    if is_single_write_cut and parsed_boundaries:
        # fault_at is 0-indexed: fault_at >= end_write means all writes of that op
        # completed before the cut.
        w21 = parsed_boundaries.get("21")
        if isinstance(w21, int) and fault_at >= w21 and mount_seq[4] != 21:
            lost_keys.append(
                {
                    "key": "k04",
                    "expected_seq": 21,
                    "actual_seq": mount_seq[4],
                    "acknowledged_at_write": w21,
                    "acknowledged_at_point": f"w[{w21}]",
                    "fault_at": fault_at,
                    "fault_point": f"w[{fault_at}]",
                    "operation_kind": "program",
                }
            )
        w23 = parsed_boundaries.get("23")
        if isinstance(w23, int) and fault_at >= w23 and mount_seq[6] not in (
            23,
            25,
            26,
            27,
            28,
            29,
            30,
        ):
            lost_keys.append(
                {
                    "key": "k06",
                    "expected_seq": 23,
                    "actual_seq": mount_seq[6],
                    "acknowledged_at_write": w23,
                    "acknowledged_at_point": f"w[{w23}]",
                    "fault_at": fault_at,
                    "fault_point": f"w[{fault_at}]",
                    "operation_kind": "program",
                }
            )
        w24 = parsed_boundaries.get("24")
        if isinstance(w24, int) and fault_at >= w24 and mount_seq[3] != 24:
            lost_keys.append(
                {
                    "key": "k03",
                    "expected_seq": 24,
                    "actual_seq": mount_seq[3],
                    "acknowledged_at_write": w24,
                    "acknowledged_at_point": f"w[{w24}]",
                    "fault_at": fault_at,
                    "fault_point": f"w[{fault_at}]",
                    "operation_kind": "program",
                }
            )

    # Causal prefix check across sequential runtime operations (21 -> 22 -> 23 -> 24).
    k5_present_at_mount = (mount_mask & (1 << 5)) != 0
    k6_present_at_mount = (mount_mask & (1 << 6)) != 0
    if not k5_present_at_mount and mount_seq[4] == 12:
        lost_keys.append(
            {
                "key": "k04",
                "expected_seq": 21,
                "actual_seq": mount_seq[4],
                "reason": "op 2 (delete k05 @ seq=22) took effect but prior op 1 (k04 @ seq=21) is missing",
            }
        )
    if k6_present_at_mount and mount_seq[4] == 12:
        lost_keys.append(
            {
                "key": "k04",
                "expected_seq": 21,
                "actual_seq": mount_seq[4],
                "reason": "op 3 (k06 @ seq=23) took effect but prior op 1 (k04 @ seq=21) is missing",
            }
        )
    if mount_seq[3] == 24 and not k6_present_at_mount:
        lost_keys.append(
            {
                "key": "k06",
                "expected_seq": 23,
                "actual_seq": mount_seq[6],
                "reason": "op 4 (k03 @ seq=24) took effect but prior op 3 (k06 @ seq=23) is missing",
            }
        )

    if lost_keys:
        issues.append(
            {
                "clause": "acknowledged_records_present",
                "finding_code": "acknowledged_record_lost_or_stale",
                "summary": f"{len(lost_keys)} acknowledged record(s) missing or rolled back to stale value",
                "lost_keys": lost_keys,
            }
        )

    # 3. Deleted keys must never reappear.
    reappeared: List[Dict[str, Any]] = []
    if (mount_mask & (1 << 2)) != 0 or mount_seq[2] != 0:
        reappeared.append(
            {
                "key": "k02",
                "stage": "mount",
                "deleted_at_seq": 11,
                "reappeared_seq": mount_seq[2],
            }
        )
    if (post_mask & (1 << 2)) != 0 or post_seq[2] != 0:
        reappeared.append(
            {
                "key": "k02",
                "stage": "post_write",
                "deleted_at_seq": 11,
                "reappeared_seq": post_seq[2],
            }
        )

    w22 = parsed_boundaries.get("22")
    write_ok = int(verdict.get("write_ok", 0))
    write_err = int(verdict.get("write_err", 0))
    post_oracle_ok = int(verdict.get("post_oracle_ok", 0))
    k5_delete_acked = (
        (is_single_write_cut and isinstance(w22, int) and fault_at >= w22)
        or k6_present_at_mount
        or mount_seq[3] == 24
    )
    if k5_delete_acked and (k5_present_at_mount or mount_seq[5] != 0):
        reappeared.append(
            {
                "key": "k05",
                "stage": "mount",
                "deleted_at_seq": 22,
                "reappeared_seq": mount_seq[5],
            }
        )
    if (k5_delete_acked or write_ok == 1) and ((post_mask & (1 << 5)) != 0 or post_seq[5] != 0):
        reappeared.append(
            {
                "key": "k05",
                "stage": "post_write",
                "deleted_at_seq": 22,
                "reappeared_seq": post_seq[5],
            }
        )

    if reappeared:
        issues.append(
            {
                "clause": "deleted_keys_stay_deleted",
                "finding_code": "deleted_key_reappeared",
                "summary": f"{len(reappeared)} deleted key(s) reappeared after recovery",
                "reappeared_keys": reappeared,
            }
        )

    # 4. Store must still accept new writes after recovery.
    if (
        write_ok != 1
        or write_err != 0
        or post_oracle_ok != 1
        or post_mask != FCB_EXPECTED_POST_MASK
    ):
        issues.append(
            {
                "clause": "store_accepts_new_writes",
                "finding_code": "post_recovery_write_failed",
                "summary": (
                    f"store failed to accept new writes after recovery "
                    f"(write_ok={write_ok}, write_err={write_err}, "
                    f"post_present_mask=0x{post_mask:02X})"
                ),
                "write_ok": write_ok,
                "write_err": write_err,
                "post_present_mask": f"0x{post_mask:02X}",
                "post_seq": post_seq,
            }
        )

    return issues


def check_zephyr_fcb_durability(result: FaultResult, **kwargs: Any) -> None:
    """Invariant check enforcing the Zephyr FCB / settings-on-FCB durability oracle."""
    result_signals = kwargs.get("result_signals")
    result_dict = kwargs.get("result_dict")
    invariant_config = kwargs.get("invariant_config")
    cfg = (
        invariant_config.get("zephyr_fcb_durability", {})
        if isinstance(invariant_config, dict)
        and isinstance(invariant_config.get("zephyr_fcb_durability"), dict)
        else {}
    )
    ack_boundaries = (
        cfg.get("ack_write_boundaries")
        if isinstance(cfg.get("ack_write_boundaries"), dict)
        else None
    )

    verdict = decode_verdict_from_signals(
        result,
        result_signals=result_signals if isinstance(result_signals, dict) else None,
        result_dict=result_dict if isinstance(result_dict, dict) else None,
    )
    if verdict is None:
        return

    fault_type = "control" if result.is_control else "w"
    if isinstance(result_dict, dict) and result_dict.get("fault_type"):
        fault_type = str(result_dict["fault_type"])
    elif getattr(result, "fault_type", None):
        fault_type = str(getattr(result, "fault_type"))

    raw_op_kind = None
    if isinstance(result_dict, dict) and result_dict.get("operation_kind"):
        raw_op_kind = str(result_dict["operation_kind"])
    elif getattr(result, "operation_kind", None):
        raw_op_kind = str(getattr(result, "operation_kind"))

    op_kind = _resolve_operation_kind(
        fault_type, raw_op_kind, is_control=bool(result.is_control)
    )

    issues = evaluate_durability_verdict(
        verdict,
        fault_at=int(result.fault_at),
        fault_type=fault_type,
        operation_kind=op_kind,
        is_control=bool(result.is_control),
        ack_write_boundaries=ack_boundaries,
    )
    if issues:
        primary = issues[0]
        summaries = "; ".join(item["summary"] for item in issues)
        details: Dict[str, Any] = {
            "finding_code": primary["finding_code"],
            "fault_at": int(result.fault_at),
            "fault_type": fault_type,
            "issues": issues,
            "mount_present_mask": f"0x{int(verdict.get('mount_present_mask', 0)):02X}",
            "mount_seq": verdict.get("mount_seq"),
            "post_present_mask": f"0x{int(verdict.get('post_present_mask', 0)):02X}",
            "post_seq": verdict.get("post_seq"),
            "write_ok": int(verdict.get("write_ok", 0)),
            "write_err": int(verdict.get("write_err", 0)),
        }
        if op_kind is not None:
            details["operation_kind"] = op_kind
            if not result.is_control and int(result.fault_at) >= 0:
                prefix = "e" if op_kind == "erase" else "w"
                details["point"] = f"{prefix}[{int(result.fault_at)}]"
        raise InvariantViolation(
            invariant_name="zephyr_fcb_durability",
            description=f"Zephyr FCB durability oracle violation: {summaries}",
            result=result,
            details=details,
        )


def parse_fcb_sector(
    sector_bytes: bytes,
    *,
    align: int = 4,
    expected_magic: int = FCB_RAW_MAGIC,
) -> Dict[str, Any]:
    """Parse an on-flash 4 KiB FCB sector for diagnostic and unit-test verification."""
    if len(sector_bytes) < 8:
        raise ValueError("FCB sector must be at least 8 bytes")
    fd_magic, fd_ver, pad, fd_id = struct.unpack_from("<IBBH", sector_bytes, 0)
    if fd_magic == 0xFFFFFFFF:
        return {
            "status": "erased",
            "fd_magic": fd_magic,
            "fd_ver": fd_ver,
            "fd_id": fd_id,
            "entries": [],
        }
    if fd_magic != expected_magic:
        return {
            "status": "corrupt_magic",
            "fd_magic": fd_magic,
            "fd_ver": fd_ver,
            "fd_id": fd_id,
            "entries": [],
        }

    header_torn = fd_ver == 0xFF and fd_id == 0xFFFF
    off = align_up(8, align)
    entries: List[Dict[str, Any]] = []
    while off + 2 <= len(sector_bytes):
        b0 = sector_bytes[off]
        b1 = sector_bytes[off + 1]
        if b0 == 0xFF and b1 == 0xFF:
            break
        if b0 & 0x80:
            data_len = (b0 & 0x7F) | (b1 << 7)
            len_cnt = 2
        else:
            data_len = b0
            len_cnt = 1
        data_off = off + align_up(len_cnt, align)
        crc_off = data_off + align_up(data_len, align)
        if crc_off + align_up(1, align) > len(sector_bytes):
            entries.append(
                {
                    "elem_off": off,
                    "data_len": data_len,
                    "crc_ok": False,
                    "status": "truncated",
                }
            )
            break
        payload = sector_bytes[data_off : data_off + data_len]
        calc_crc = crc8_ccitt(0xFF, sector_bytes[off : off + len_cnt] + payload)
        flash_crc = sector_bytes[crc_off]
        entries.append(
            {
                "elem_off": off,
                "data_off": data_off,
                "data_len": data_len,
                "flash_crc": flash_crc,
                "calc_crc": calc_crc,
                "crc_ok": flash_crc == calc_crc,
                "payload": payload,
            }
        )
        off = crc_off + align_up(1, align)

    return {
        "status": "torn_header" if header_torn else "active",
        "fd_magic": fd_magic,
        "fd_ver": fd_ver,
        "fd_id": fd_id,
        "fd_id_signed": struct.unpack("<h", struct.pack("<H", fd_id))[0],
        "entries": entries,
    }


def register_invariants() -> Dict[str, Any]:
    return {"zephyr_fcb_durability": check_zephyr_fcb_durability}
