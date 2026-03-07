"""Simplified environment pool for libCRS-backed environments.

Replaces OssFuzzEnvironmentPool — no caching, no debug/valgrind variants.
The builder sidecar manages snapshots via OSS_CRS_SNAPSHOT_IMAGE.
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
        builder: str,
        source_directory: Path,
    ) -> None:
        self._source_directory = source_directory
        self._environment = LibCRSEnvironment(
            crs=crs,
            builder=builder,
            source_directory=source_directory,
        )

    @property
    def source_directory(self) -> Path:
        return self._source_directory

    @property
    def environment(self) -> LibCRSEnvironment:
        return self._environment

    def restore(self) -> LibCRSEnvironment:
        """Restore source and return the environment."""
        self._environment.restore()
        return self._environment

    def internal_test_exists(self) -> bool:
        """Check if a test script exists. Always False in libCRS mode.

        In oss-crs, tests are run via the builder sidecar's run_test endpoint,
        not via a local test.sh script. The DockerEvaluator checks this method
        to decide whether to run tests.
        """
        return False
