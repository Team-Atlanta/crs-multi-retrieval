"""Crash analysis pipeline: parse crash logs, extract stack traces, classify bugs.

Consolidates models, patterns, and analysis functions for both C/C++ (userland)
and JVM (Jazzer) crash output.
"""

import glob
import logging
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, TypeAlias

from pydantic import BaseModel, Field

from crete.atoms.detection import Detection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models (from crash_analysis/models.py)
# ---------------------------------------------------------------------------


class FunctionFrame(BaseModel):
    """A resolved function frame from a crash stack trace."""

    model_config = {"frozen": True}

    function_name: str
    file: Path
    line: int
    line_number_in_log: int

    def __hash__(self) -> int:
        return hash(
            (self.function_name, str(self.file), self.line, self.line_number_in_log)
        )


class InvalidFrame(BaseModel):
    """Placeholder for a frame that could not be resolved."""

    model_config = {"frozen": True}

    function_name: str = "invalid"
    file: Path = Path("")
    line: int = 0
    line_number_in_log: int = 0

    def __hash__(self) -> int:
        return hash(
            (self.function_name, str(self.file), self.line, self.line_number_in_log)
        )


class CrashStack(BaseModel):
    """A single crash stack: ordered frames plus the sanitizer entry index."""

    model_config = {"frozen": True}

    frames: list[FunctionFrame]
    sanitizer_index: int

    def iter_relevant_frames(
        self, depth: int | None = None
    ) -> Iterator[tuple[int, FunctionFrame]]:
        frames = self.frames[self.sanitizer_index :]
        if depth is not None:
            frames = frames[:depth]
        return enumerate(frames, start=self.sanitizer_index)


class CrashAnalysisResult(BaseModel):
    """Full crash analysis output: raw bytes plus parsed stacks."""

    model_config = {"frozen": True}

    output: bytes = b""
    crash_stacks: list[CrashStack] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Type aliases (from crash_analysis/types.py)
# ---------------------------------------------------------------------------

Frame: TypeAlias = FunctionFrame | InvalidFrame
CrashStacks: TypeAlias = list[CrashStack]
CrashAnalyzer: TypeAlias = Callable[[Path, bytes], CrashAnalysisResult]


# ---------------------------------------------------------------------------
# Bug class patterns (from crash_analysis/patterns.py)
# ---------------------------------------------------------------------------

BUG_CLASS_PATTERNS: list[str] = [
    # c/c++
    r"ERROR: (AddressSanitizer: [\w-]+): ",
    r"ERROR: (AddressSanitizer: [\w-]+) ",
    r"ERROR: (AddressSanitizer: global-buffer-overflow)",
    r"ERROR: (UndefinedBehaviorSanitizer: [\w-]+) ",
    r"ERROR: (ThreadSanitizer: [\w-]+) ",
    r"(runtime error: .+): ",
    r"(MemorySanitizer: [\w-]+) ",
    r"(LeakSanitizer: ([\w-]+) )",
    # java
    r"== Java Exception: (com.code_intelligence.jazzer.api.FuzzerSecurityIssue\w+: .+):",
    r"== Java Exception: (com.code_intelligence.jazzer.api.FuzzerSecurityIssue\w+: .+)",
    r"== Java Exception: ([\w.]+Error): ",
    r"== Java Exception: ([\w.]+Exception): ",
    # python
    r"===BUG DETECTED: (PySecSan: .+) ===",
    r"=== (Uncaught Python exception): ===",
    r"(Uncaught Exception): Error: Check index! Data Corrupted!",
    # libfuzzer
    r"== ERROR: libFuzzer: (.*)",
]


# ---------------------------------------------------------------------------
# resolve_project_path (from environment/functions.py — pure filesystem logic)
# ---------------------------------------------------------------------------


def resolve_project_path(
    file: Path,
    source_directory: Path,
    *,
    only_file: bool = True,
) -> Path | None:
    """Resolve *file* relative to *source_directory* (direct then rglob)."""
    for sub_path in _get_relative_sub_paths(file):
        resolved_path = (source_directory / sub_path).resolve()
        if resolved_path.exists() and (resolved_path.is_file() if only_file else True):
            return resolved_path

    for sub_path in _get_relative_sub_paths(file):
        if resolved_path := _find_sub_path_matching_file(
            source_directory, sub_path, only_file=only_file
        ):
            return resolved_path

    return None


def _get_relative_sub_paths(path: Path) -> list[Path]:
    return [
        Path(*path.parts[i:])
        for i in range(len(path.parts))
        if not Path(*path.parts[i:]).is_absolute()
    ]


def _find_sub_path_matching_file(
    source_directory: Path,
    sub_path: Path,
    *,
    only_file: bool = True,
) -> Path | None:
    if sub_path.is_absolute():
        return None

    source_directory = source_directory.resolve()

    for path in source_directory.rglob(sub_path.name):
        if (
            path.is_file()
            and path.as_posix().endswith(sub_path.as_posix())
            and (not only_file or path.is_file())
        ):
            return path

    return None


# ---------------------------------------------------------------------------
# Core crash parsing (from crash_analysis/functions/common.py)
# ---------------------------------------------------------------------------


def _append_crash_stack_if_not_empty(
    crash_stacks: CrashStacks,
    frames: list[FunctionFrame],
    find_sanitizer_index_fn: Callable[[list[FunctionFrame]], int],
) -> None:
    if len(frames) == 0:
        return
    crash_stacks.append(
        CrashStack(frames=frames, sanitizer_index=find_sanitizer_index_fn(frames))
    )


def analyze_crash(
    source_directory: Path,
    output_preprocessing_fn: Callable[[bytes], list[bytes]],
    line_to_frame_fn: Callable[[bytes, int, Path], Frame | None],
    find_sanitizer_index_fn: Callable[[list[FunctionFrame]], int],
    output: bytes,
) -> CrashAnalysisResult:
    """Generic crash analysis: preprocess → parse lines → build CrashStacks."""
    blocks = output_preprocessing_fn(output)

    crash_stacks: CrashStacks = []
    for block in blocks:
        frames: list[FunctionFrame] = []
        for index, line in enumerate(block.splitlines()):
            frame = line_to_frame_fn(line, index, source_directory)

            match frame:
                case FunctionFrame():
                    frames.append(frame)
                case InvalidFrame():
                    pass
                case None:
                    _append_crash_stack_if_not_empty(
                        crash_stacks, frames, find_sanitizer_index_fn
                    )
                    frames = []

        _append_crash_stack_if_not_empty(crash_stacks, frames, find_sanitizer_index_fn)

    return CrashAnalysisResult(
        output=b"".join(blocks),
        crash_stacks=crash_stacks,
    )


# ---------------------------------------------------------------------------
# Jazzer (JVM) crash analysis (from functions/jazzer_crash.py)
# ---------------------------------------------------------------------------

_jazzer_frame_regex = re.compile(rb"^\s*at (?:(.+)\.)?(.+)\.(.+)\((.+\.java):(\d+)\)$")


def analyze_jazzer_crash(source_directory: Path, output: bytes) -> CrashAnalysisResult:
    """Analyse a JVM Jazzer crash output."""
    path_map = _create_path_map(source_directory)

    return analyze_crash(
        source_directory=source_directory,
        output_preprocessing_fn=jazzer_output_preprocess,
        line_to_frame_fn=_jazzer_line_to_frame(path_map),
        find_sanitizer_index_fn=_jazzer_find_sanitizer_index,
        output=output,
    )


def _create_path_map(source_directory: Path) -> list[Path]:
    return [
        Path(file)
        for file in glob.glob("**/*.java", root_dir=source_directory, recursive=True)
    ]


def jazzer_output_preprocess(output: bytes) -> list[bytes]:
    if b"== Java Exception:" in output:
        output = output[output.index(b"== Java Exception:") :]
    if b"== ERROR: libFuzzer:" in output:
        output = output[output.index(b"== ERROR: libFuzzer:") :]
    return [output]


def _jazzer_line_to_frame(
    path_map: list[Path],
) -> Callable[[bytes, int, Path], Frame | None]:
    def _inner(
        line: bytes,
        line_number_in_log: int,
        source_directory: Path,
    ) -> Frame | None:
        return _jazzer_line_to_frame_with_path_map(
            line, line_number_in_log, source_directory, path_map
        )

    return _inner


def _jazzer_line_to_frame_with_path_map(
    line: bytes,
    line_number_in_log: int,
    source_directory: Path,
    path_map: list[Path],
) -> Frame | None:
    matched = _jazzer_frame_regex.match(line)
    if matched is None:
        return None

    package_name = matched.group(1).decode() if matched.group(1) else ""
    _class_name = matched.group(2).decode()
    method_name = matched.group(3).decode()
    file_name = matched.group(4).decode()
    line_number = int(matched.group(5).decode()) - 1

    file_path = (
        Path(*package_name.split(".")) / file_name if package_name else Path(file_name)
    )

    resolved_path_candidates = [f for f in path_map if str(f).endswith(str(file_path))]

    if len(resolved_path_candidates) > 0:
        resolved_path = resolve_project_path(
            resolved_path_candidates[0], source_directory
        )
        if resolved_path is not None:
            return FunctionFrame(
                function_name=method_name,
                file=resolved_path,
                line=line_number,
                line_number_in_log=line_number_in_log,
            )

    return InvalidFrame()


def _jazzer_find_sanitizer_index(frames: list[FunctionFrame]) -> int:
    return 0


# ---------------------------------------------------------------------------
# Userland (C/C++) crash analysis (from functions/userland_crash.py)
# ---------------------------------------------------------------------------

_asan_frame_regex = re.compile(rb"^\s+#\d+ 0x[0-9a-f]+ in (.+) ([^:]+):(\d+)(?::\d+)?$")
_asan_weak_frame_regex = re.compile(rb"^\s+#\d+ 0x[0-9a-f]+ in (.+)$")
_ubsan_frame_regex = re.compile(rb"^\s+#\d+ 0x[0-9a-f]+ in (.+)$")


def analyze_userland_crash(
    source_directory: Path, output: bytes
) -> CrashAnalysisResult:
    """Analyse a C/C++ crash output (ASan, UBSan, etc.)."""
    return analyze_crash(
        source_directory=source_directory,
        output_preprocessing_fn=userland_output_preprocess,
        line_to_frame_fn=_userland_line_to_frame,
        find_sanitizer_index_fn=_userland_find_sanitizer_index,
        output=output,
    )


def _find_by_regex(output: bytes, pattern: bytes, start: int) -> tuple[int, int] | None:
    match = re.search(pattern, output[start:])
    if match is None:
        return None
    return match.start(0), match.end(0) - match.start(0)


def userland_output_preprocess(output: bytes) -> list[bytes]:
    segments: list[int] = []
    current_position = 0

    while True:
        matches = [
            _find_by_regex(output, pattern, current_position)
            for pattern in [
                rb"([^\n:]+:\d+:\d+: runtime error: )",
                b"==ERROR: UndefinedBehaviorSanitizer:",
                b"==ERROR: AddressSanitizer:",
                b"== ERROR: libFuzzer:",
                b"==WARNING: MemorySanitizer:",
                b"==ERROR: MemorySanitizer:",
                b"==ERROR: LeakSanitizer:",
            ]
        ]

        if all(m is None for m in matches):
            segments.append(len(output))
            break

        start, length = min(m for m in matches if m is not None)

        assert length > 0, "Length of the match should be greater than 0"

        segments.append(current_position + start)
        current_position += start + length

    return [output[s:e] for s, e in zip(segments, segments[1:])]


def _userland_line_to_frame(
    line: bytes,
    line_number_in_log: int,
    source_directory: Path,
) -> Frame | None:
    return _line_to_asan_frame(
        line, line_number_in_log, source_directory
    ) or _line_to_ubsan_frame(line, line_number_in_log, source_directory)


def _line_to_asan_frame(
    line: bytes,
    line_number_in_log: int,
    source_directory: Path,
) -> Frame | None:
    match = _asan_weak_frame_regex.match(line)
    if match is None:
        return None

    match = _asan_frame_regex.match(line)
    if match is None:
        return InvalidFrame()

    function_name = match.group(1).decode()
    file = resolve_project_path(Path(match.group(2).decode()), source_directory)
    line_number = int(match.group(3)) - 1

    if file is None:
        return InvalidFrame()

    return FunctionFrame(
        function_name=function_name,
        file=file,
        line=line_number,
        line_number_in_log=line_number_in_log,
    )


def _line_to_ubsan_frame(
    line: bytes,
    line_number_in_log: int,
    source_directory: Path,
) -> Frame | None:
    match = _ubsan_frame_regex.match(line)
    if match is None:
        return None

    return InvalidFrame()


def _userland_find_sanitizer_index(frames: list[FunctionFrame]) -> int:
    return 0


# ---------------------------------------------------------------------------
# Public API — high-level crash analysis functions
# ---------------------------------------------------------------------------


def get_crash_stacks(
    context: dict[str, Any], detection: Detection
) -> CrashStacks | None:
    """Extract crash stack traces from a detection's crash output."""
    if crash_analysis_result := get_crash_analysis_results(context, detection):
        return crash_analysis_result.crash_stacks
    return None


def get_crash_analysis_results(
    context: dict[str, Any], detection: Detection
) -> CrashAnalysisResult | None:
    """Full crash analysis pipeline: get crash log → parse → return results."""
    crash_log_analyzer = context.get("crash_log_analyzer")
    if crash_log_analyzer is None:
        return None

    pov_output = crash_log_analyzer.analyze(context, detection)
    if pov_output is None:
        return None

    crash_analyzer = _get_crash_analyzer(detection)
    source_directory = context["pool"].source_directory
    crash_analysis_results = crash_analyzer(source_directory, pov_output)

    if len(crash_analysis_results.crash_stacks) == 0:
        logger.warning("Crash analysis results is empty. This should not happen.")
        return None

    return crash_analysis_results


def get_bug_class(context: dict[str, Any], detection: Detection) -> str | None:
    """Determine vulnerability type from crash data or SARIF report."""
    crash_log_analyzer = context.get("crash_log_analyzer")
    if crash_log_analyzer is not None:
        crash_log = crash_log_analyzer.analyze(context, detection)
        if crash_log is not None:
            return extract_bug_class(crash_log.decode(errors="replace"))

    sarif_report = detection.sarif_report
    if sarif_report is not None:
        # Simple SARIF rule extraction (no DefaultSarifParser dependency)
        for run in sarif_report.runs:
            results = run.get("results")  # type: ignore[union-attr]
            if results is None:
                continue
            for result in results:
                rule_id = result.get("ruleId")  # type: ignore[union-attr]
                if rule_id is not None:
                    return str(rule_id)

    return None


def extract_bug_class(crash_log: str) -> str | None:
    """Extract bug class string from raw crash log text using regex patterns."""
    for pattern in BUG_CLASS_PATTERNS:
        match = re.search(pattern, crash_log)
        if match:
            return match.group(1)
    return None


def _get_crash_analyzer(detection: Detection) -> CrashAnalyzer:
    match detection.language:
        case "c" | "cpp" | "c++":
            return analyze_userland_crash
        case "jvm":
            return analyze_jazzer_crash
        case _:
            raise ValueError(f"Unsupported language: {detection.language}")
