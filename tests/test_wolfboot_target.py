# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the wolfBoot build driver and recovery profiles."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import load_profile  # noqa: E402


class WolfBootTargetTests(unittest.TestCase):
    def test_pinned_repositories_and_commits_are_complete_sha1(self) -> None:
        import build_wolfboot

        self.assertEqual(
            build_wolfboot.WOLFBOOT_REPO_URL,
            "https://github.com/wolfSSL/wolfBoot.git",
        )
        self.assertEqual(
            build_wolfboot.WOLFBOOT_COMMIT,
            "ad8dc62131fc0067a3ab25edc1b7e731397712d4",
        )
        self.assertEqual(
            build_wolfboot.WOLFBOOT_WOLFSSL_SUBMODULE_COMMIT,
            "f8a805dd64321bb4b396b99fa99b170b5b9cd3d7",
        )
        self.assertEqual(
            build_wolfboot.OPENBLT_REPO_URL,
            "https://github.com/feaser/openblt.git",
        )
        self.assertEqual(
            build_wolfboot.OPENBLT_COMMIT,
            "64beeee6f24490f7ca3373185bfcd3188a6d3b15",
        )
        for commit in (
            build_wolfboot.WOLFBOOT_COMMIT,
            build_wolfboot.WOLFBOOT_WOLFSSL_SUBMODULE_COMMIT,
            build_wolfboot.OPENBLT_COMMIT,
        ):
            self.assertIsNotNone(build_wolfboot.FULL_SHA1_RE.fullmatch(commit))

    def test_work_dir_must_be_external_or_git_ignored(self) -> None:
        import build_wolfboot

        self.assertEqual(
            build_wolfboot._validate_work_dir(
                ROOT / "build" / "wolfboot"
            ),
            (ROOT / "build" / "wolfboot").resolve(),
        )
        with self.assertRaisesRegex(
            build_wolfboot.TargetBuildError, "not Git-ignored"
        ):
            build_wolfboot._validate_work_dir(
                ROOT / "unignored_checkout"
            )
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(
                build_wolfboot._validate_work_dir(Path(td)),
                Path(td).resolve(),
            )

    def test_tracked_change_parser_includes_submodule_and_rename_paths(self) -> None:
        import build_wolfboot

        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                " M src/changed.c\n"
                "M  staged.c\n"
                " R old.c -> renamed.c\n"
                " M lib/wolfssl\n"
                "?? ignored-by-command.c\n"
            ),
            stderr="",
        )
        original_run = build_wolfboot._run
        try:
            build_wolfboot._run = lambda *args, **kwargs: completed
            self.assertEqual(
                build_wolfboot._modified_tracked_paths(Path("unused")),
                ["lib/wolfssl", "renamed.c", "src/changed.c", "staged.c"],
            )
        finally:
            build_wolfboot._run = original_run

    def test_openblt_rule3_blocker_inspector_reports_missing_rollback_and_drivers(
        self,
    ) -> None:
        import build_wolfboot

        with tempfile.TemporaryDirectory() as td:
            checkout = Path(td)
            blockers = build_wolfboot.inspect_openblt_blockers(checkout)
            self.assertEqual(len(blockers), 3)
            files = [item["file"] for item in blockers]
            self.assertIn("Target/Source/boot.h", files)
            self.assertIn("Target/Source/boot.c", files)
            self.assertIn(
                "Target/Demo/ARMCM4_STM32F4_Nucleo_F429ZI_GCC/Boot/blt_conf.h",
                files,
            )
            self.assertEqual(
                [(item["file"], item["lines"]) for item in blockers],
                [
                    ("Target/Source/boot.h", "71-73"),
                    ("Target/Source/boot.c", "40-106"),
                    (
                        "Target/Demo/ARMCM4_STM32F4_Nucleo_F429ZI_GCC/Boot/"
                        "blt_conf.h",
                        "113,127,164",
                    ),
                ],
            )
            err = build_wolfboot.UnmodifiedSourceBlockerError(
                "OpenBLT", blockers
            )
            self.assertIn("Hard Rule 3", str(err))
            self.assertIn("Target/Source/boot.h:71-73", str(err))

    def test_wolfboot_profiles_load_in_strict_mode_with_target_source(self) -> None:
        control = load_profile(
            ROOT / "profiles" / "wolfboot_stm32f4_control.yaml", strict=True
        )
        sweep = load_profile(
            ROOT / "profiles" / "wolfboot_stm32f4_power_loss_erase.yaml",
            strict=True,
        )
        state_search = load_profile(
            ROOT / "profiles" / "wolfboot_stm32f4_state_search.yaml",
            strict=True,
        )

        for profile in (control, sweep, state_search):
            self.assertIsNotNone(profile.target_source)
            assert profile.target_source is not None
            self.assertEqual(profile.target_source.name, "wolfboot")
            self.assertEqual(
                profile.target_source.repository,
                "https://github.com/wolfSSL/wolfBoot.git",
            )
            self.assertEqual(
                profile.target_source.revision,
                "ad8dc62131fc0067a3ab25edc1b7e731397712d4",
            )
            self.assertTrue(profile.fault_sweep.include_erase_fault_points)
            self.assertEqual(profile.success_criteria.vector_table_offset, 0x100)
            self.assertTrue(profile.success_criteria.image_hash)

        self.assertEqual(control.fault_sweep.max_writes, 0)
        self.assertEqual(control.success_criteria.expected_image, "staging")
        self.assertEqual(control.success_criteria.marker_value, 2)
        self.assertEqual(control.success_criteria.allowed_images, [])
        for profile in (sweep, state_search):
            with self.subTest(profile=profile.name):
                criteria = profile.success_criteria
                self.assertEqual(criteria.allowed_images, ["exec", "staging"])
                self.assertIsNone(criteria.expected_image)
                self.assertIsNone(criteria.marker_value)
                self.assertEqual(criteria.image_hash_slot, "exec")
                self.assertEqual(criteria.vtor_in_slot, "exec")
        self.assertEqual(sweep.fault_sweep.max_writes, "auto")
        self.assertTrue(state_search.fault_sweep.phase2_fault.enabled)
        self.assertTrue(
            state_search.fault_sweep.phase2_fault.state_search.enabled
        )
        self.assertEqual(
            state_search.fault_sweep.phase2_fault.fault_types,
            ["power_loss", "interrupted_erase"],
        )

    def test_gitignore_excludes_target_inputs_and_outputs(self) -> None:
        for candidate in (
            "build/wolfboot/sources/wolfBoot/wolfboot.elf",
            "results/wolfboot/control.json",
            "targets/wolfboot/upstream/openblt/README.md",
            "targets/wolfboot/build/wolfboot.bin",
        ):
            completed = subprocess.run(
                ["git", "-C", str(ROOT), "check-ignore", "-q", candidate],
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                f"Expected .gitignore to ignore {candidate}",
            )


if __name__ == "__main__":
    unittest.main()
