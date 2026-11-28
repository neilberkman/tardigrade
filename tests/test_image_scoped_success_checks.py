"""Profile and standalone reproduction coverage for image-scoped checks."""

import ast
import base64
import json
from pathlib import Path
import struct
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from audit_report import categorize_failure  # noqa: E402
from export_repro import _render_reproduce_recovery_py  # noqa: E402
from profile_loader import ProfileError, load_profile  # noqa: E402
from result_checks import annotate_result_checks  # noqa: E402
from sweep import evaluate_config_checks  # noqa: E402


def _write_test_elf(path: Path, symbols: dict[str, int]) -> None:
    """Write a minimal 32-bit little-endian ARM ELF with .symtab and .strtab."""
    shstrtab = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    strtab = bytearray(b"\x00")
    sym_entries = [struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)]
    for name, address in symbols.items():
        name_offset = len(strtab)
        strtab.extend(name.encode("utf-8") + b"\x00")
        st_info = (1 << 4) | 1  # STB_GLOBAL | STT_OBJECT
        sym_entries.append(
            struct.pack("<IIIBBH", name_offset, int(address), 4, st_info, 0, 1)
        )
    symtab = b"".join(sym_entries)
    ehdr_size = 52
    text_offset = ehdr_size
    text_data = b"\x00\xbf\x00\xbf"
    symtab_offset = text_offset + len(text_data)
    strtab_offset = symtab_offset + len(symtab)
    shstrtab_offset = strtab_offset + len(strtab)
    shdr_offset = (shstrtab_offset + len(shstrtab) + 3) & ~3
    pad = b"\x00" * (shdr_offset - (shstrtab_offset + len(shstrtab)))

    def shdr(name_off, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link=0, sh_info=0, sh_align=1, sh_entsize=0):
        return struct.pack(
            "<10I",
            name_off, sh_type, sh_flags, sh_addr, sh_off,
            sh_size, sh_link, sh_info, sh_align, sh_entsize,
        )

    shdrs = b"".join([
        shdr(0, 0, 0, 0, 0, 0),
        shdr(1, 1, 6, 0x10100000, text_offset, len(text_data), sh_align=4),
        shdr(7, 2, 0, 0, symtab_offset, len(symtab), sh_link=3, sh_info=1, sh_align=4, sh_entsize=16),
        shdr(15, 3, 0, 0, strtab_offset, len(strtab)),
        shdr(23, 3, 0, 0, shstrtab_offset, len(shstrtab)),
    ])
    e_ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2, 40, 1, 0x10100000, 0, shdr_offset, 0x05000000,
        ehdr_size, 0, 0, 40, 5, 4,
    )
    path.write_bytes(ehdr + text_data + symtab + bytes(strtab) + shstrtab + pad + shdrs)


def _load(tmp_path, *, evaluation_mode="execute", strict=True, overrides=None, **criteria):
    for name in ("old", "new"):
        (tmp_path / (name + ".bin")).write_bytes(name.encode())
    raw = {
        "schema_version": 1,
        "name": "scoped_checks",
        "platform": "platforms/cortex_m0_self_update.repl",
        "bootloader": {"elf": "boot.elf", "entry": 0},
        "memory": {
            "sram": {"start": 0x20000000, "end": 0x20002000},
            "write_granularity": 4,
            "slots": {
                "exec": {"base": 0x10100000, "size": 0x1000},
                "staging": {"base": 0x10101000, "size": 0x1000},
            },
        },
        "images": {"exec": "old.bin", "staging": "new.bin"},
        "success_criteria": {"image_hash": True, **criteria},
        "fault_sweep": {"mode": "runtime", "evaluation_mode": evaluation_mode},
    }
    if overrides:
        raw["success_criteria_overrides"] = overrides
    path = tmp_path / "profile.yaml"
    path.write_text(yaml.safe_dump(raw))
    return load_profile(path, strict=strict)


def test_image_scope_and_width_survive_strict_loading_and_robot_transport(tmp_path):
    profile = _load(
        tmp_path,
        allowed_images=["exec", "staging"],
        memory_checks=[
            {"address": 0x20000000, "expected_value": 1},
            {"image": "exec", "address": 0x20000200, "width": 1, "expected_value": 3},
        ],
        config_checks=[{"image": "staging", "address": 0x20000300, "expected": 2}],
    )
    robot_vars = dict(value.split(":", 1) for value in profile.robot_vars(ROOT))
    payload = json.loads(base64.b64decode(robot_vars["SUCCESS_CHECKS_B64"]))
    global_check, scoped_check = payload["memory_checks"]
    assert "image" not in global_check
    assert (scoped_check["image"], scoped_check["width"]) == ("exec", 1)
    assert payload["config_checks"][0]["image"] == "staging"


@pytest.mark.parametrize(
    ("images", "image", "message"),
    [
        (None, "exec", "must name a member"),
        (["exec", "staging"], "missing", "must name a member"),
        (["exec", "staging"], None, "non-empty image name"),
    ],
)
def test_profile_refuses_unusable_image_scopes(tmp_path, images, image, message):
    with pytest.raises(ProfileError, match=message):
        _load(
            tmp_path,
            allowed_images=images,
            memory_checks=[{"image": image, "address": 0x20000200, "op": "nonzero"}],
        )


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        ({"evaluation_mode": "state"}, "require fault_sweep.evaluation_mode: execute"),
        ({"overrides": {"power_loss": {"image_hash": False}}}, "require image_hash"),
    ],
)
def test_scoped_checks_refuse_boot_paths_without_digest_evidence(tmp_path, settings, message):
    with pytest.raises(ProfileError, match=message):
        _load(
            tmp_path, strict=False, **settings,
            allowed_images=["exec", "staging"],
            config_checks=[{"image": "exec", "address": 0x20000200, "nonzero": True}],
        )


def test_exported_runner_checks_the_matched_image_with_runtime_mask_semantics():
    tree = ast.parse(_render_reproduce_recovery_py())
    wanted = {"evaluate_success_checks", "match_allowed_image"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    assert {node.name for node in functions} == wanted
    namespace = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "<reproducer>", "exec"), namespace)

    class Bus:
        def ReadByte(self, address):
            assert address == 0x20000300
            return 0xA2

        def ReadDoubleWord(self, address):
            assert address == 0x20000040
            return 1

    digest = "22" * 32
    matched = namespace["match_allowed_image"](
        digest,
        [{"name": "exec", "sha256": "11" * 32}, {"name": "staging", "sha256": digest}],
    )
    config = {
        "memory_checks": [
            {"image": "exec", "address": 0x20000200, "expected_value": 1},
            {"image": "staging", "address": 0x20000300, "width": 1,
             "mask": 0x0F, "expected_value": 0xF2},
        ],
        "config_checks": [
            {"image": "staging", "address": 0x20000040, "expected": 1},
        ],
    }
    checks = namespace["evaluate_success_checks"](config, Bus(), int, hex, matched)
    assert checks["all_ok"] is True
    assert checks["matched_image"] == "staging"
    memory, = checks["memory_checks"]
    assert (memory["index"], memory["image"], memory["actual_masked"]) == (1, "staging", 2)
    assert checks["config_checks"][0]["image"] == "staging"


def test_symbol_checks_resolve_per_allowed_image_and_evaluate(tmp_path):
    _write_test_elf(tmp_path / "old.elf", {"alive": 0x20000200, "cfg_word": 0x20000204})
    _write_test_elf(tmp_path / "new.elf", {"alive": 0x20000300, "cfg_word": 0x20000304})
    profile = _load(
        tmp_path,
        allowed_images=["exec", "staging"],
        memory_checks=[
            {"symbol": "alive", "op": "nonzero"},
            {"image": "staging", "symbol": "alive", "width": 1, "expected_value": 2},
        ],
        config_checks=[
            {"symbol": "cfg_word", "expected": 0x55},
        ],
    )
    unscoped_mem, scoped_mem = profile.success_criteria.memory_checks
    assert unscoped_mem.image_addresses == {"exec": 0x20000200, "staging": 0x20000300}
    assert scoped_mem.address == 0x20000300
    assert profile.success_criteria.config_checks[0].image_addresses == {
        "exec": 0x20000204,
        "staging": 0x20000304,
    }

    robot_vars = dict(value.split(":", 1) for value in profile.robot_vars(ROOT))
    payload = json.loads(base64.b64decode(robot_vars["SUCCESS_CHECKS_B64"]))
    assert payload["memory_checks"][0]["symbol"] == "alive"
    assert payload["memory_checks"][0]["addresses"] == {"exec": 0x20000200, "staging": 0x20000300}

    tree = ast.parse(_render_reproduce_recovery_py())
    wanted = {"evaluate_success_checks", "has_image_scoped_checks"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    namespace = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "<reproducer>", "exec"), namespace)
    assert namespace["has_image_scoped_checks"](payload) is True

    class Bus:
        def ReadByte(self, address):
            assert address == 0x20000300
            return 2

        def ReadDoubleWord(self, address):
            return {0x20000200: 1, 0x20000204: 0x55, 0x20000300: 2, 0x20000304: 0x55}[address]

    exec_obs = namespace["evaluate_success_checks"](payload, Bus(), int, hex, "exec")
    assert exec_obs["all_ok"] is True
    assert [(c["symbol"], c["image"], c["address"]) for c in exec_obs["memory_checks"]] == [
        ("alive", "exec", "0x20000200"),
    ]
    assert evaluate_config_checks(
        {
            "boot_outcome": "success",
            "matched_allowed_image": "exec",
            "config_values": exec_obs["config_values"],
        },
        profile,
    ) is None

    staging_obs = namespace["evaluate_success_checks"](payload, Bus(), int, hex, "staging")
    assert staging_obs["all_ok"] is True
    assert [(c["symbol"], c["image"], c["address"]) for c in staging_obs["memory_checks"]] == [
        ("alive", "staging", "0x20000300"),
        ("alive", "staging", "0x20000300"),
    ]


@pytest.mark.parametrize(
    ("allowed_images", "check", "overrides", "message"),
    [
        (["exec", "staging"], {"address": 0x20000200, "symbol": "alive", "op": "nonzero"}, None, "either address or symbol"),
        (["exec", "staging"], {"symbol": " ", "op": "nonzero"}, None, "non-empty symbol name"),
        (None, {"symbol": "alive", "op": "nonzero"}, None, "requires success_criteria.allowed_images"),
        (["exec", "staging"], {"symbol": "missing_sym", "op": "nonzero"}, None, "not found"),
        (
            ["exec", "staging"],
            {"symbol": "alive", "op": "nonzero"},
            {"power_loss": {"memory_checks": [{"symbol": "alive", "op": "nonzero"}]}},
            "declare image-scoped checks in success_criteria",
        ),
    ],
)
def test_profile_refuses_invalid_symbol_checks(tmp_path, allowed_images, check, overrides, message):
    _write_test_elf(tmp_path / "old.elf", {"alive": 0x20000200})
    _write_test_elf(tmp_path / "new.elf", {"alive": 0x20000300})
    with pytest.raises(ProfileError, match=message):
        _load(
            tmp_path,
            strict=False,
            allowed_images=allowed_images,
            overrides=overrides,
            memory_checks=[check],
        )


def test_result_annotation_and_failure_categorization_preserve_matched_allowed_image(tmp_path):
    profile = _load(
        tmp_path,
        allowed_images=["exec", "staging"],
        memory_checks=[{"image": "exec", "address": 0x20000200, "expected_value": 1}],
    )
    result = {
        "fault_at": 0,
        "fault_type": "e",
        "fault_injected": True,
        "boot_outcome": "memory_checks_unmet",
        "boot_slot": "exec",
        "signals": {
            "matched_image": "exec",
            "matched_allowed_image": "exec",
            "success_checks": {
                "contract_version": 1,
                "requested": True,
                "all_ok": False,
                "matched_image": "exec",
                "memory_checks_ok": False,
                "memory_checks": [
                    {"index": 0, "image": "exec", "address": "0x20000200", "ok": False},
                ],
            },
            "failed_memory_checks": [
                {
                    "index": 0,
                    "image": "exec",
                    "address": "0x20000200",
                    "summary": "image exec: memory_check[0] @ 0x20000200: actual 0x00000000 (0) does not satisfy eq 1",
                }
            ],
            "unmet_memory_checks": [
                "image exec: memory_check[0] @ 0x20000200: actual 0x00000000 (0) does not satisfy eq 1"
            ],
        },
    }
    annotate_result_checks([result], profile, repo_root=ROOT)
    assert result["matched_allowed_image"] == "exec"
    assert result["success_checks"]["matched_image"] == "exec"
    categorized = categorize_failure(result, 64, profile=profile)
    assert categorized["matched_allowed_image"] == "exec"
    assert categorized["success_checks"]["matched_image"] == "exec"
    assert categorized["failed_memory_checks"][0]["image"] == "exec"
