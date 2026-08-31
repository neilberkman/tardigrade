from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import fuzzer_harness  # noqa: E402


def _config(tmp_path: Path, command: list[str]) -> dict:
    valid = tmp_path / "valid.bin"
    invalid = tmp_path / "invalid.bin"
    valid.write_bytes(b"valid")
    invalid.write_bytes(b"invalid")
    return {
        "command": command,
        "valid_seed": str(valid),
        "invalid_seed": str(invalid),
        "valid": {"outcome": True},
        "invalid": {"outcome": False},
        "timeout_seconds": 1,
        "outcome_field": "accepted",
    }


def _write_harness(tmp_path: Path, *, behavior: str = "normal") -> Path:
    path = tmp_path / "harness.py"
    path.write_text(
        "import json, pathlib, sys, time\n"
        "data = pathlib.Path(sys.argv[1]).read_bytes()\n"
        + ("time.sleep(2)\n" if behavior == "timeout" else "")
        + ("raise SystemExit(3)\n" if behavior == "abort" else "")
        + "print(json.dumps({'accepted': data == b'valid'}))\n",
        encoding="utf-8",
    )
    return path


def test_valid_and_invalid_controls_pass(tmp_path: Path) -> None:
    harness = _write_harness(tmp_path)
    result = fuzzer_harness.qualify_harness(_config(tmp_path, [sys.executable, str(harness), "{input}"]))
    assert result["status"] == "PASS"
    assert result["product_findings"] == []
    assert [item["status"] for item in result["cases"]] == ["PASS", "PASS"]


@pytest.mark.parametrize("behavior,reason", [("abort", "expected exit"), ("timeout", "timed out")])
def test_abort_and_timeout_are_infrastructure_failures(tmp_path: Path, behavior: str, reason: str) -> None:
    harness = _write_harness(tmp_path, behavior=behavior)
    result = fuzzer_harness.qualify_harness(_config(tmp_path, [sys.executable, str(harness), "{input}"]))
    assert result["status"] == "INFRASTRUCTURE_FAILURE"
    assert result["product_findings"] == []
    assert any(reason in item["reason"] for item in result["cases"])


def test_malformed_json_is_infrastructure_failure(tmp_path: Path) -> None:
    harness = tmp_path / "bad.py"
    harness.write_text("print('not json')\n", encoding="utf-8")
    result = fuzzer_harness.qualify_harness(_config(tmp_path, [sys.executable, str(harness), "{input}"]))
    assert result["status"] == "INFRASTRUCTURE_FAILURE"
    assert result["cases"][0]["reason"] == "harness output is not JSON"


def test_malformed_utf8_output_is_infrastructure_failure(tmp_path: Path) -> None:
    harness = tmp_path / "bad_utf8.py"
    harness.write_text(
        "import sys\n"
        "sys.stdout.buffer.write(b'\\xff')\n",
        encoding="utf-8",
    )
    result = fuzzer_harness.qualify_harness(
        _config(tmp_path, [sys.executable, str(harness), "{input}"])
    )
    assert result["status"] == "INFRASTRUCTURE_FAILURE"
    assert result["product_findings"] == []
    assert all(item["status"] == "INFRASTRUCTURE_FAILURE" for item in result["cases"])


def test_missing_seed_is_infrastructure_failure(tmp_path: Path) -> None:
    harness = _write_harness(tmp_path)
    config = _config(tmp_path, [sys.executable, str(harness), "{input}"])
    Path(config["invalid_seed"]).unlink()
    result = fuzzer_harness.qualify_harness(config)
    assert result["status"] == "INFRASTRUCTURE_FAILURE"
    assert result["product_findings"] == []
    assert result["cases"][1]["status"] == "INFRASTRUCTURE_FAILURE"


def test_read_error_is_infrastructure_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _write_harness(tmp_path)
    config = _config(tmp_path, [sys.executable, str(harness), "{input}"])
    invalid_seed = Path(config["invalid_seed"])
    original_read_bytes = Path.read_bytes

    def fail_invalid_seed(path: Path) -> bytes:
        if path == invalid_seed:
            raise OSError("synthetic read failure")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_invalid_seed)
    result = fuzzer_harness.qualify_harness(config)
    assert result["status"] == "INFRASTRUCTURE_FAILURE"
    assert result["product_findings"] == []
    assert "could not be read" in result["cases"][1]["reason"]


def test_same_declared_outcome_is_rejected(tmp_path: Path) -> None:
    harness = _write_harness(tmp_path)
    config = _config(tmp_path, [sys.executable, str(harness), "{input}"])
    config["invalid"]["outcome"] = True
    with pytest.raises(fuzzer_harness.HarnessPreflightError, match="opposite outcomes"):
        fuzzer_harness.qualify_harness(config)


def test_nonzero_expected_exit_is_rejected(tmp_path: Path) -> None:
    harness = _write_harness(tmp_path)
    config = _config(tmp_path, [sys.executable, str(harness), "{input}"])
    config["invalid"] = {"exit_code": 1}
    with pytest.raises(fuzzer_harness.HarnessPreflightError, match="exit_code must be 0"):
        fuzzer_harness.qualify_harness(config)


def test_byte_identical_controls_are_rejected(tmp_path: Path) -> None:
    harness = _write_harness(tmp_path)
    config = _config(tmp_path, [sys.executable, str(harness), "{input}"])
    Path(config["invalid_seed"]).write_bytes(Path(config["valid_seed"]).read_bytes())
    with pytest.raises(fuzzer_harness.HarnessPreflightError, match="byte-identical"):
        fuzzer_harness.qualify_harness(config)


def test_relative_paths_resolve_from_config_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    harness = _write_harness(config_dir)
    config = _config(config_dir, [sys.executable, harness.name, "{input}"])
    config["valid_seed"] = "valid.bin"
    config["invalid_seed"] = "invalid.bin"
    config["cwd"] = "."
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    result = fuzzer_harness.qualify_harness(config, base_dir=config_dir)
    assert result["status"] == "PASS"


def test_harness_receives_opaque_staged_seed_paths(tmp_path: Path) -> None:
    harness = tmp_path / "opaque.py"
    harness.write_text(
        "import json, pathlib, sys\n"
        "path = pathlib.Path(sys.argv[1])\n"
        "assert 'valid' not in path.name and 'invalid' not in path.name\n"
        "print(json.dumps({'accepted': path.read_bytes() == b'valid'}))\n",
        encoding="utf-8",
    )
    result = fuzzer_harness.qualify_harness(
        _config(tmp_path, [sys.executable, str(harness), "{input}"])
    )
    assert result["status"] == "PASS"


def test_existing_seed_is_staged_when_peer_is_missing(tmp_path: Path) -> None:
    harness = tmp_path / "opaque.py"
    harness.write_text(
        "import json, pathlib, sys\n"
        "path = pathlib.Path(sys.argv[1])\n"
        "assert 'valid' not in path.name and 'invalid' not in path.name\n"
        "print(json.dumps({'accepted': True}))\n",
        encoding="utf-8",
    )
    config = _config(tmp_path, [sys.executable, str(harness), "{input}"])
    Path(config["invalid_seed"]).unlink()
    # The valid control still runs against a temporary opaque path; its peer
    # is missing, so the overall result remains an infrastructure failure.
    result = fuzzer_harness.qualify_harness(config)
    assert result["status"] == "INFRASTRUCTURE_FAILURE"
    assert result["cases"][0]["status"] == "PASS"
    assert result["cases"][1]["status"] == "INFRASTRUCTURE_FAILURE"


def test_case_label_placeholder_is_rejected(tmp_path: Path) -> None:
    harness = _write_harness(tmp_path)
    config = _config(
        tmp_path, [sys.executable, str(harness), "{input}", "{case}"]
    )
    with pytest.raises(fuzzer_harness.HarnessPreflightError, match="unknown placeholder"):
        fuzzer_harness.qualify_harness(config)
