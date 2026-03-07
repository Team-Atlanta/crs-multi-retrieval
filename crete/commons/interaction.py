"""Command interaction utilities: subprocess execution, exceptions, and ANSI stripping."""

import os
import re
import signal
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path

_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

_Command = tuple[str | Sequence[str], Path]


class CommandInteractionError(Exception):
    """Raised when a subprocess exits with a non-zero return code."""

    __match_args__ = ("stdout", "stderr", "return_code")

    def __init__(self, stdout: bytes, stderr: bytes, return_code: int) -> None:
        super().__init__(
            f"Command failed with return code {return_code}\n\n"
            f"stdout: {stdout}\n\nstderr: {stderr}"
        )
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code


class TimeoutExpired(Exception):
    """Raised when a subprocess exceeds the allowed timeout."""

    __match_args__ = ("stdout", "stderr")

    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        super().__init__("Command timed out")
        self.stdout = stdout
        self.stderr = stderr


def remove_ansi_escape_codes(text: str | bytes) -> str:
    """Strip ANSI escape sequences from a string or bytes value."""
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    return _ANSI_ESCAPE_PATTERN.sub("", text)


def run_command(
    command: _Command,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    input_data: bytes | None = None,
    *,
    no_color: bool = False,
) -> tuple[str, str]:
    """Execute a shell command and return (stdout, stderr).

    Raises:
        CommandInteractionError: on non-zero exit.
        TimeoutExpired: if the process exceeds *timeout* seconds.
    """
    if no_color:
        return _run_command_without_color(command, timeout, env, input_data)
    return _run_command(command, timeout, env, input_data)


def _run_command_without_color(
    command: _Command,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    input_data: bytes | None = None,
) -> tuple[str, str]:
    try:
        stdout, stderr = _run_command(command, timeout, env, input_data)
        return remove_ansi_escape_codes(stdout), remove_ansi_escape_codes(stderr)
    except CommandInteractionError as exc:
        raise CommandInteractionError(
            stdout=remove_ansi_escape_codes(exc.stdout).encode(),
            stderr=remove_ansi_escape_codes(exc.stderr).encode(),
            return_code=exc.return_code,
        ) from exc
    except TimeoutExpired as exc:
        raise TimeoutExpired(
            stdout=remove_ansi_escape_codes(exc.stdout).encode(),
            stderr=remove_ansi_escape_codes(exc.stderr).encode(),
        ) from exc


def _run_command(
    command: _Command,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    input_data: bytes | None = None,
) -> tuple[str, str]:
    line, cwd = command

    process = subprocess.Popen(
        line,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=isinstance(line, str),
        env=env,
    )

    try:
        stdout, stderr = process.communicate(input=input_data, timeout=timeout)
        return_code = process.returncode

        match return_code:
            case 0:
                return (
                    stdout.decode(errors="ignore"),
                    stderr.decode(errors="ignore"),
                )
            case _:
                raise CommandInteractionError(
                    stdout=stdout, stderr=stderr, return_code=return_code
                )
    except subprocess.TimeoutExpired as error:
        os.kill(process.pid, signal.SIGINT)
        time.sleep(5)
        _kill_process_tree(process.pid)
        stdout, stderr = process.communicate()
        raise TimeoutExpired(stdout=stdout, stderr=stderr) from error


def _kill_process_tree(pid: int) -> None:
    """Kill a process and all its children (best-effort)."""
    try:
        import psutil

        psutil_process = psutil.Process(pid)
        children = psutil_process.children(recursive=True)
        for child in reversed(children):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        try:
            psutil_process.kill()
        except psutil.NoSuchProcess:
            pass
    except ImportError:
        # psutil not available — fall back to basic kill
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
