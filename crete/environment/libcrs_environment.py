"""LibCRS-backed environment replacing OssFuzzEnvironment.

Uses libCRS API (apply_patch_build, run_pov, run_test) instead of
helper.py / Docker commands. Source restoration uses local git reset.
"""

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from crete.environment.exceptions import (
    ChallengeBuildFailedError,
    ChallengePoVFoundError,
    ChallengeTestFailedError,
)

logger = logging.getLogger(__name__)


class LibCRSEnvironment:
    """Environment backed by libCRS builder sidecar.

    Replaces OssFuzzEnvironment. All build/run operations delegate to
    CRSUtils (apply_patch_build, run_pov, run_test) instead of
    helper.py shell commands.
    """

    def __init__(
        self,
        crs: Any,
        builder: str,
        source_directory: Path,
    ) -> None:
        self._crs = crs
        self._builder = builder
        self._source_directory = source_directory

    @property
    def source_directory(self) -> Path:
        return self._source_directory

    def restore(self) -> None:
        """Reset source directory to HEAD using local git."""
        for lock_file in self._source_directory.glob(".git/**/*.lock"):
            logger.warning("Removing stale lock file: %s", lock_file)
            lock_file.unlink()

        subprocess.run(
            ["git", "reset", "--hard", "HEAD"],
            cwd=self._source_directory,
            capture_output=True,
            timeout=60,
        )
        subprocess.run(
            ["git", "clean", "-fd"],
            cwd=self._source_directory,
            capture_output=True,
            timeout=60,
        )

    def build(self, response_dir: Path) -> tuple[str, str]:
        """Build via libCRS apply_patch_build with an empty diff.

        Returns (stdout, stderr) from the build logs.
        Raises ChallengeBuildFailedError on non-zero exit code.
        """
        with tempfile.NamedTemporaryFile(
            suffix=".diff", delete_on_close=False
        ) as diff_file:
            diff_file.write(b"")
            diff_file.close()

            exit_code = self._crs.apply_patch_build(
                Path(diff_file.name), response_dir, self._builder
            )

        return self._handle_build_result(exit_code, response_dir)

    def patch(self, patch_data: Path | bytes, response_dir: Path) -> tuple[str, str]:
        """Apply a patch and build via libCRS.

        Args:
            patch_data: Either a path to a diff file or raw diff bytes.
            response_dir: Directory for libCRS to write build logs.

        Returns (stdout, stderr) from the build logs.
        Raises ChallengeBuildFailedError on build failure.
        """
        match patch_data:
            case Path():
                exit_code = self._crs.apply_patch_build(
                    patch_data, response_dir, self._builder
                )
            case bytes():
                with tempfile.NamedTemporaryFile(
                    suffix=".diff", delete_on_close=False
                ) as diff_file:
                    diff_file.write(patch_data)
                    diff_file.close()

                    exit_code = self._crs.apply_patch_build(
                        Path(diff_file.name), response_dir, self._builder
                    )

        return self._handle_build_result(exit_code, response_dir)

    def run_pov(
        self,
        pov_path: Path,
        harness_name: str,
        build_id: str,
        response_dir: Path,
    ) -> tuple[str, str]:
        """Run a PoV via libCRS.

        Returns (stdout, stderr) if no crash (exit code 0).
        Raises ChallengePoVFoundError if crash detected (non-zero exit).
        """
        exit_code = self._crs.run_pov(
            pov_path, harness_name, build_id, response_dir, self._builder
        )

        stdout = self._read_log(response_dir, "pov_stdout.log")
        stderr = self._read_log(response_dir, "pov_stderr.log")

        if exit_code != 0:
            raise ChallengePoVFoundError(
                stdout=stdout.encode(errors="replace"),
                stderr=stderr.encode(errors="replace"),
            )

        return stdout, stderr

    def run_tests(self, build_id: str, response_dir: Path) -> tuple[str, str]:
        """Run tests via libCRS.

        Returns (stdout, stderr) on success.
        Raises ChallengeTestFailedError on non-zero exit.
        """
        exit_code = self._crs.run_test(build_id, response_dir, self._builder)

        stdout = self._read_log(response_dir, "test_stdout.log")
        stderr = self._read_log(response_dir, "test_stderr.log")

        if exit_code != 0:
            raise ChallengeTestFailedError(
                stdout=stdout.encode(errors="replace"),
                stderr=stderr.encode(errors="replace"),
            )

        return stdout, stderr

    def _handle_build_result(
        self, exit_code: int, response_dir: Path
    ) -> tuple[str, str]:
        """Read build logs and raise on failure."""
        stdout = self._read_log(response_dir, "build_stdout.log")
        stderr = self._read_log(response_dir, "build_stderr.log")

        if exit_code != 0:
            raise ChallengeBuildFailedError(
                stdout=stdout.encode(errors="replace"),
                stderr=stderr.encode(errors="replace"),
            )

        return stdout, stderr

    @staticmethod
    def read_build_id(response_dir: Path) -> str:
        """Read the build_id written by libCRS after apply_patch_build.

        Falls back to ``"base"`` if the file does not exist (e.g. when
        the build was never triggered).
        """
        build_id_path = response_dir / "build_id"
        if not build_id_path.exists():
            logger.warning("build_id file not found in %s, defaulting to 'base'", response_dir)
            return "base"
        return build_id_path.read_text().strip()

    @staticmethod
    def _read_log(response_dir: Path, filename: str) -> str:
        """Read a log file from response_dir, returning empty string if absent."""
        log_path = response_dir / filename
        if not log_path.exists():
            return ""
        return log_path.read_text(errors="replace")
