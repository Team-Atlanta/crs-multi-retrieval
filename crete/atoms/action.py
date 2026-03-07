import random
from pathlib import Path
from typing import Literal, TypeAlias

from pydantic import BaseModel, Field

ActionVariant: TypeAlias = Literal[
    "sound",
    "vulnerable",
    "compilable",
    "uncompilable",
    "wrong",
    "no_patch",
    "unknown_error",
    "head",
]

ACTION_SCORES: dict[str, int] = {
    "SoundDiffAction": 4,
    "VulnerableDiffAction": 3,
    "CompilableDiffAction": 3,
    "UncompilableDiffAction": 2,
    "WrongDiffAction": 1,
    "NoPatchAction": 0,
    "UnknownErrorAction": -1,
    "HeadAction": -2,
}


class BaseAction(BaseModel):
    variant: ActionVariant


class DiffAction(BaseAction):
    diff: bytes

    def __str__(self) -> str:
        return f"{self.variant.capitalize()}DiffAction(diff={self.diff})"


class SoundDiffAction(DiffAction):
    variant: ActionVariant = Field(default="sound")
    diff: bytes


class VulnerableDiffAction(DiffAction):
    variant: ActionVariant = Field(default="vulnerable")
    diff: bytes
    stdout: bytes
    stderr: bytes


class CompilableDiffAction(DiffAction):
    variant: ActionVariant = Field(default="compilable")
    diff: bytes
    stdout: bytes
    stderr: bytes


class UncompilableDiffAction(DiffAction):
    variant: ActionVariant = Field(default="uncompilable")
    diff: bytes
    stdout: bytes
    stderr: bytes


class WrongDiffAction(DiffAction):
    variant: ActionVariant = Field(default="wrong")
    diff: bytes
    stdout: bytes
    stderr: bytes


class NoPatchAction(BaseAction):
    variant: ActionVariant = Field(default="no_patch")

    def __str__(self) -> str:
        return "NoPatchAction()"


class UnknownErrorAction(BaseAction):
    variant: ActionVariant = Field(default="unknown_error")
    error: Exception

    model_config = {"arbitrary_types_allowed": True}

    def __str__(self) -> str:
        return f"UnknownErrorAction(error={self.error})"


class HeadAction(BaseAction):
    variant: ActionVariant = Field(default="head")

    def __str__(self) -> str:
        return "HeadAction()"


Action: TypeAlias = (
    SoundDiffAction
    | VulnerableDiffAction
    | CompilableDiffAction
    | UncompilableDiffAction
    | WrongDiffAction
    | NoPatchAction
    | UnknownErrorAction
    | HeadAction
)


def get_score(action: Action) -> int:
    return ACTION_SCORES[type(action).__name__]


def store_action(action: Action, output_directory: Path, prefix: str) -> None:
    (output_directory / f"{prefix}-action.json").write_text(
        action.model_dump_json(indent=2)
    )

    match action:
        case HeadAction():
            (output_directory / f"{prefix}-action-head.empty").touch()
        case SoundDiffAction(variant=variant, diff=diff):
            (output_directory / f"{prefix}-action-sound.diff").write_bytes(diff)
        case (
            VulnerableDiffAction(variant=variant, diff=diff)
            | CompilableDiffAction(variant=variant, diff=diff)
            | UncompilableDiffAction(variant=variant, diff=diff)
            | WrongDiffAction(variant=variant, diff=diff)
        ):
            (output_directory / f"{prefix}-action-{variant}.diff").write_bytes(diff)
            (output_directory / f"{prefix}-action-{variant}.stdout").write_bytes(
                action.stdout
            )
            (output_directory / f"{prefix}-action-{variant}.stderr").write_bytes(
                action.stderr
            )
        case NoPatchAction():
            (output_directory / f"{prefix}-action-no_patch.empty").touch()
        case UnknownErrorAction(error=error):
            with open(
                output_directory / f"{prefix}-action-unknown_error.error", "w"
            ) as f:
                f.write(f"Exception type: {type(error).__name__}\n")
                f.write(f"Exception message: {error!s}\n")


def choose_best_action(actions: list[Action]) -> Action:
    assert len(actions) >= 1, "To choose the best action, at least one action is needed"
    max_score = max(get_score(action) for action in actions)
    best_actions = [action for action in actions if get_score(action) == max_score]
    return random.choice(best_actions)
