"""DefaultEvaluator — orchestrates the evaluate-patch cycle.

Flow: restore → patch+build → run PoV → run tests → restore.
Returns an Action based on the outcome at each stage.
Uses LibCRSEnvironment via EnvironmentPool for all operations.
"""

import logging
import tempfile
from pathlib import Path
from typing import Any

from crete.atoms.action import (
    Action,
    CompilableDiffAction,
    SoundDiffAction,
    UncompilableDiffAction,
    UnknownErrorAction,
    VulnerableDiffAction,
    WrongDiffAction,
)
from crete.atoms.detection import Detection
from crete.environment.environment_pool import EnvironmentPool
from crete.environment.exceptions import (
    ChallengeBuildFailedError,
    ChallengePoVFoundError,
    ChallengeTestFailedError,
    ChallengeWrongPatchError,
)
from crete.environment.libcrs_environment import LibCRSEnvironment

logger = logging.getLogger(__name__)


class DefaultEvaluator:
    """Evaluates a diff against the libCRS environment.

    Orchestrates: restore → patch+build → run_pov → run_tests → restore.
    Returns the appropriate Action type for each failure mode.
    """

    def __init__(
        self,
        pool: EnvironmentPool,
        *,
        response_dir: Path | None = None,
    ) -> None:
        self._pool = pool
        self._response_dir = response_dir

    def _get_response_dir(self) -> Path:
        """Return configured response_dir or create a temp directory."""
        if self._response_dir is not None:
            self._response_dir.mkdir(parents=True, exist_ok=True)
            return self._response_dir
        return Path(tempfile.mkdtemp(prefix="crs-eval-"))

    def evaluate(
        self,
        context: dict[str, Any],
        diff: bytes,
        detection: Detection,
    ) -> Action:
        """Evaluate a patch diff and return the resulting Action.

        Flow:
        1. Restore source to clean state
        2. Apply patch and build → WrongDiffAction or UncompilableDiffAction on failure
        3. Run PoV → VulnerableDiffAction if crash still triggers
        4. Run tests → CompilableDiffAction if tests fail
        5. All pass → SoundDiffAction

        Always restores source at the end regardless of outcome.
        """
        try:
            return self._evaluate_internal(context, diff, detection)
        finally:
            self._pool.restore()

    def _evaluate_internal(
        self,
        context: dict[str, Any],
        diff: bytes,
        detection: Detection,
    ) -> Action:
        environment = self._pool.environment
        response_dir = self._get_response_dir()

        # Step 1: Patch + Build
        try:
            environment.patch(diff, response_dir)
        except ChallengeWrongPatchError as exc:
            logger.exception("Failed to apply the patch")
            return WrongDiffAction(
                diff=diff,
                stdout=exc.stdout,
                stderr=exc.stderr,
            )
        except ChallengeBuildFailedError as exc:
            logger.error("Failed to build the challenge")
            return UncompilableDiffAction(
                diff=diff,
                stdout=exc.stdout,
                stderr=exc.stderr,
            )
        except Exception as exc:
            logger.exception("Unknown error occurred during patch/build")
            return UnknownErrorAction(error=exc)

        build_id = LibCRSEnvironment.read_build_id(response_dir)

        # Step 2: Run PoV
        try:
            if len(detection.blobs) > 0:
                blob = detection.blobs[0]
                # Write blob data to temp file for PoV execution
                with tempfile.NamedTemporaryFile(
                    suffix=".pov", delete_on_close=False
                ) as pov_file:
                    pov_file.write(blob.blob)
                    pov_file.close()
                    pov_stdout, pov_stderr = environment.run_pov(
                        pov_path=Path(pov_file.name),
                        harness_name=blob.harness_name,
                        build_id=build_id,
                        response_dir=response_dir,
                    )
                # Store stderr in context for JVM analyzers
                context["run_pov_stderr"] = pov_stderr
            else:
                logger.warning("No blob data found for the detection")
        except ChallengePoVFoundError as exc:
            logger.error("PoV still triggers after patch: %s", exc)
            return VulnerableDiffAction(
                diff=diff,
                stdout=exc.stdout,
                stderr=exc.stderr,
            )
        except Exception as exc:
            logger.exception("Unknown error occurred during PoV execution")
            return UnknownErrorAction(error=exc)

        # Step 3: Run Tests
        try:
            environment.run_tests(
                build_id=build_id,
                response_dir=response_dir,
            )
        except ChallengeTestFailedError as exc:
            logger.exception("Tests failed after patch")
            return CompilableDiffAction(
                diff=diff,
                stdout=exc.stdout,
                stderr=exc.stderr,
            )
        except Exception as exc:
            logger.exception("Unknown error occurred during test execution")
            return UnknownErrorAction(error=exc)

        return SoundDiffAction(diff=diff)
