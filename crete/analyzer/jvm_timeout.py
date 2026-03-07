"""JVM timeout stacktrace analyzer — adapted for libCRS (no Docker-in-Docker).

Original ran ``reproduce_extended`` + ``jstack`` to capture timeout stack traces.
This adaptation parses timeout info from ``run_pov`` stderr instead, which already
contains Jazzer stack traces when a timeout occurs.
"""

import logging
from typing import Any

from crete.atoms.detection import Detection

logger = logging.getLogger(__name__)

_TIMEOUT_MARKER = "ERROR: libFuzzer: timeout"


class JVMTimeoutStacktraceAnalyzer:
    """Extract timeout stack traces from run_pov stderr.

    Looks for ``ERROR: libFuzzer: timeout`` in the stderr produced by the
    most recent ``run_pov`` call and returns the relevant bytes for downstream
    crash analysis.
    """

    def analyze(
        self,
        context: dict[str, Any],
        detection: Detection,
    ) -> bytes | None:
        assert detection.language == "jvm", (
            "JVMTimeoutStacktraceAnalyzer is only supported for JVM projects"
        )

        # Retrieve stderr from the most recent run_pov invocation.
        # libCRS stores it in context after run_pov completes.
        run_pov_stderr: bytes | str | None = context.get("run_pov_stderr")
        if run_pov_stderr is None:
            logger.warning("No run_pov stderr available for timeout analysis")
            return None

        if isinstance(run_pov_stderr, str):
            run_pov_stderr = run_pov_stderr.encode()

        stderr_text = run_pov_stderr.decode(errors="replace")

        if _TIMEOUT_MARKER not in stderr_text:
            logger.info("No timeout marker found in run_pov stderr")
            return None

        # Return the stderr from the timeout marker onward — it contains
        # the Jazzer stack trace that would previously have come from jstack.
        timeout_index = stderr_text.index(_TIMEOUT_MARKER)
        timeout_output = stderr_text[timeout_index:]

        logger.info("Extracted timeout stacktrace from run_pov stderr")
        return timeout_output.encode()
