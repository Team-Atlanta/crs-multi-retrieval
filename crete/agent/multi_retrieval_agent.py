import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages.utils import convert_to_openai_messages  # type: ignore[import-untyped]

from crete.agent.context import AgentContext
from crete.atoms.action import Action, NoPatchAction
from crete.atoms.detection import Detection
from crete.state.patch_state import PatchState
from crete.workflow.system_guided_patch_workflow import SystemGuidedPatchWorkflow

logger = logging.getLogger(__name__)


class MultiRetrievalPatchAgent:
    """Top-level agent that orchestrates the LangGraph workflow.

    Uses ChatLiteLLM (BaseChatModel) directly instead of LlmApiManager.
    Iterates through the workflow graph and yields Actions.
    """

    def __init__(
        self,
        llm: BaseChatModel,
        backup_llm: BaseChatModel | None = None,
        *,
        recursion_limit: int = 64,
        max_n_evals: int = 4,
    ) -> None:
        self._llm = llm
        self._backup_llm = backup_llm
        self.recursion_limit = recursion_limit
        self.workflow = SystemGuidedPatchWorkflow(max_n_evals=max_n_evals)
        self.workflow.compile(llm=self._llm)

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        self.workflow.update(context, detection)

        final_diff = None
        try:
            patch_state = self.workflow.invoke(
                PatchState(repo_path=str(context["pool"].patch_directory)),
                {"recursion_limit": self.recursion_limit},
            )

            final_diff = patch_state["diff"]
            output_directory = context.get("output_directory")
            if output_directory is not None:
                self._log_state_to_file(
                    output_directory,
                    patch_state,
                    _get_model_name(self._llm),
                )
        except Exception:
            logger.warning("Error occurred while generating patch", exc_info=True)
            final_diff = self._patch_with_backup_llm(context)

        if final_diff is None or len(final_diff.strip()) == 0:
            yield NoPatchAction()
        else:
            yield context["evaluator"].evaluate(
                context, bytes(final_diff, "utf-8"), detection
            )

    def _patch_with_backup_llm(self, context: AgentContext) -> str | None:
        final_diff = None
        if self._backup_llm is None:
            return final_diff
        logger.info("MultiRetrieval patching with backup LLM...")
        try:
            self.workflow.set_llm(self._backup_llm)
            patch_state = self.workflow.invoke(
                PatchState(repo_path=str(context["pool"].patch_directory)),
                {"recursion_limit": self.recursion_limit},
            )
            final_diff = patch_state["diff"]
            output_directory = context.get("output_directory")
            if output_directory is not None:
                self._log_state_to_file(
                    output_directory,
                    patch_state,
                    _get_model_name(self._backup_llm),
                )
        except Exception:
            logger.error(
                "Error occurred while generating patch(backup)",
                exc_info=True,
            )
        return final_diff

    def _log_state_to_file(
        self,
        output_directory: Path,
        state: dict[str, Any] | Any,
        model: str,
    ) -> None:
        saved_state: dict[str, Any] = {
            "model": model,
            "messages": convert_to_openai_messages(state["messages"]),
            "diff": state["diff"],
            "n_evals": state["n_evals"],
            "tests_log": state["tests_log"],
        }

        saved_content = json.dumps(saved_state, ensure_ascii=False, indent=4)
        output_path = Path(output_directory) / "messages.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(saved_content, encoding="utf-8")


def _get_model_name(llm: BaseChatModel) -> str:
    """Extract model name from a BaseChatModel instance."""
    if hasattr(llm, "model"):
        return str(llm.model)
    if hasattr(llm, "model_name"):
        return str(llm.model_name)
    return str(type(llm).__name__)
