"""JVM stack overflow stacktrace analyzer — adapted for libCRS (no Docker/jdb).

Original ran ``run_jdb_commands`` to attach a debugger and capture the stack
overflow trace.  This adaptation parses the raw stack overflow trace from
``run_pov`` stderr and applies ``deduplicate_consecutive_frames`` to compress
repeated frame patterns.
"""

import logging
import re
from typing import Any

from crete.atoms.detection import Detection

logger = logging.getLogger(__name__)

_STACKOVERFLOW_MARKER = "FuzzerSecurityIssueLow: Stack overflow"


def _is_same_block(block1: list[str], block2: list[str]) -> bool:
    """Compare two frame blocks after anonymizing numeric indices.

    Block format example::

        [8,081] java.util.AbstractSet.hashCode (AbstractSet.java:124)
        [8,082] java.util.AbstractSet.hashCode (AbstractSet.java:124)
    """

    def anonymize_block(block: str) -> str:
        return re.sub(r"\[\d[\d,]*\]", "[<anon>]", block, flags=re.DOTALL)

    return all(
        anonymize_block(b1) == anonymize_block(b2) for b1, b2 in zip(block1, block2)
    )


def deduplicate_consecutive_frames(
    stacktrace: str,
    max_cycle_size: int = 5,
    repeat_threshold: int = 3,
) -> str:
    """Compress repeated frame patterns in JVM stack traces.

    Pure Python cycle detection: finds consecutive identical frame blocks
    and replaces them with a single block + ``... (repeated N times)``.
    """
    assert max_cycle_size > 0, "max_cycle_size must be positive"
    assert repeat_threshold >= 3, (
        "repeat_threshold must be at least 3 to insert '... (repeated N times)' "
        "with previous line and next line"
    )

    idx = 0
    result: list[str] = []
    lines = stacktrace.split("\n")
    while idx < len(lines):
        found_repeat = False
        for cycle_size in range(1, max_cycle_size + 1):
            block = lines[idx : idx + cycle_size]
            j = idx + cycle_size
            repeat_count = 0
            while j + cycle_size < len(lines) and _is_same_block(
                block, lines[j : j + cycle_size]
            ):
                repeat_count += 1
                j += cycle_size
            if repeat_count >= repeat_threshold:
                result.extend(block)
                result.append(f"... (repeated {repeat_count - 1} times)")
                result.extend(lines[j - cycle_size : j])
                idx = j
                found_repeat = True
                break
        if not found_repeat:
            result.append(lines[idx])
            idx += 1
    return "\n".join(result)


class JVMStackOverflowStacktraceAnalyzer:
    """Extract and deduplicate stack overflow traces from run_pov stderr.

    Instead of running ``jdb`` inside Docker, reads the raw stack overflow
    trace from ``run_pov`` stderr and applies frame deduplication.
    """

    def analyze(
        self,
        context: dict[str, Any],
        detection: Detection,
    ) -> str | None:
        assert detection.language == "jvm", (
            "JVMStackOverflowStacktraceAnalyzer is only supported for JVM projects"
        )
        logger.info("Analyzing JVM stackoverflow stacktrace")

        # Retrieve stderr from the most recent run_pov invocation
        run_pov_stderr: bytes | str | None = context.get("run_pov_stderr")
        if run_pov_stderr is None:
            logger.warning("No run_pov stderr available for stackoverflow analysis")
            return None

        if isinstance(run_pov_stderr, bytes):
            run_pov_stderr = run_pov_stderr.decode(errors="replace")

        if _STACKOVERFLOW_MARKER not in run_pov_stderr:
            logger.info("No stack overflow marker found in run_pov stderr")
            return None

        # Extract the stack trace portion after the marker
        raw_stacktrace = run_pov_stderr.split(_STACKOVERFLOW_MARKER, 1)[-1].strip("\n")

        compact_stacktrace = deduplicate_consecutive_frames(raw_stacktrace)
        logger.info("Stacktrace: %s", compact_stacktrace)
        return compact_stacktrace
