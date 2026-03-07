"""Challenge environment exceptions.

Ported from atlantis-crete's environment/exceptions.py.
All exceptions carry stdout and stderr bytes for error reporting.
"""


class ChallengeBuildFailedError(Exception):
    __match_args__ = ("stdout", "stderr")

    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        super().__init__(
            "Build failed:\n"
            f"- Stdout:\n{stdout.decode(errors='replace')}\n"
            f"- Stderr:\n{stderr.decode(errors='replace')}\n"
        )
        self.stdout = stdout
        self.stderr = stderr


class ChallengePoVFoundError(Exception):
    __match_args__ = ("stdout", "stderr")

    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        super().__init__(
            "PoV found:\n"
            f"- Stdout:\n{stdout.decode(errors='replace')}\n"
            f"- Stderr:\n{stderr.decode(errors='replace')}\n"
        )
        self.stdout = stdout
        self.stderr = stderr


class ChallengeTestFailedError(Exception):
    __match_args__ = ("stdout", "stderr")

    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        super().__init__(
            "Test failed:\n"
            f"- Stdout:\n{stdout.decode(errors='replace')}\n"
            f"- Stderr:\n{stderr.decode(errors='replace')}\n"
        )
        self.stdout = stdout
        self.stderr = stderr


class ChallengeWrongPatchError(Exception):
    __match_args__ = ("stdout", "stderr")

    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        super().__init__(
            "Wrong patch:\n"
            f"- Stdout:\n{stdout.decode(errors='replace')}\n"
            f"- Stderr:\n{stderr.decode(errors='replace')}\n"
        )
        self.stdout = stdout
        self.stderr = stderr
