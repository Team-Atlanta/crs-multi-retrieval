"""Simplified environment pool for libCRS-backed environments.

Replaces OssFuzzEnvironmentPool — no caching, no debug/valgrind variants.
Builder and runner sidecars are injected automatically by the framework.
"""

import logging
from pathlib import Path
from typing import Any

from crete.environment.libcrs_environment import LibCRSEnvironment

logger = logging.getLogger(__name__)


class EnvironmentPool:
    """Single-environment pool backed by libCRS.

    Simplified from OssFuzzEnvironmentPool:
    - No CachedOssFuzzEnvironment (builder sidecar manages snapshots)
    - No debug/valgrind/call-trace environment variants
    - No rsync-based save/load
    - Single LibCRSEnvironment instance
    """

    def __init__(
        self,
        crs: Any,
        source_directory: Path,
    ) -> None:
        self._source_directory = source_directory
        self._crs = crs
        self._patch_directory: Path | None = None
        self._environment = LibCRSEnvironment(
            crs=crs,
            source_directory=source_directory,
        )

    @property
    def source_directory(self) -> Path:
        return self._source_directory

    @property
    def patch_directory(self) -> Path:
        """Clean target-source tree for patch generation.

        Downloaded once via ``libCRS download-source target-source``.
        The fuzz-proj ``source_directory`` may contain nested git repos
        (submodules) that break ``git diff``, so patches must be created
        from this clean tree instead.
        """
        if self._patch_directory is None:
            dst = self._source_directory.parent / "patch-src"
            from libCRS.base import SourceType
            self._crs.download_source(SourceType.TARGET_SOURCE, dst)
            self._patch_directory = dst
            logger.info("Downloaded clean target-source to %s", dst)
        return self._patch_directory

    @property
    def environment(self) -> LibCRSEnvironment:
        return self._environment

    def restore(self, _context: object | None = None) -> LibCRSEnvironment:
        """Restore patch directory to HEAD and return the environment."""
        self._environment.restore()
        if self._patch_directory is not None:
            self._environment.restore_directory(self._patch_directory)
        return self._environment

    def internal_test_exists(self) -> bool:
        """Check if a test script exists. Always False in libCRS mode.

        In oss-crs, tests are run via the builder sidecar's apply_patch_test endpoint,
        not via a local test.sh script. The DockerEvaluator checks this method
        to decide whether to run tests.
        """
        return False
