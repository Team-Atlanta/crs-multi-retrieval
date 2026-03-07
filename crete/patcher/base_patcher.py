import inspect
import re

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage

from crete.patcher.line_range_patch_extractor import LineRangePatchExtractor
from crete.patcher.llm_node import LLMNode
from crete.state.patch_state import CodeDiff, CodeSnippet, PatchState


class BasePatcher(LLMNode):
    failed_patches_prompt: str = inspect.cleandoc(
        """
        Failed to generate patches for the following locations:
        {failed_patches}

        Possible reasons for the failed patches:
        - Incorrect format, indentation, whitespace or newline characters.
        - Incorrect or different indentation levels.
        - Omitted or abbreviated contents.
        - Incorrect line ranges or file path.
        - Overlapping line ranges provided for multiple patches.
        - Trying to patch a file that does not exist in the repository.

        Please regenerate the patches for the failed locations.
        """
    )
    incorrect_format_prompt: str = "Failed to extract the patch. Please ensure the patch is in the correct format with <patch> and </patch> tags."

    patch_regex = re.compile(r"(?:<patch>)([\s\S]*?)(?:<\/patch>)")

    def __init__(
        self,
        llm: BaseChatModel,
        max_n_retries: int = 3,
    ) -> None:
        super().__init__(llm)
        self.max_n_retries = max_n_retries
        self.patch_extractor = LineRangePatchExtractor()

    def _extract_and_add_patches(
        self, state: PatchState, code_diff: CodeDiff, repo_path: str
    ) -> None:
        last_message_content = self._check_content_is_str(
            state.messages[-1].content  # type: ignore[union-attr]
        )
        patch_regex_matches = self.patch_regex.findall(last_message_content)
        if len(patch_regex_matches) == 0:
            for _ in range(self.max_n_retries):
                state.messages.append(HumanMessage(self.incorrect_format_prompt))
                state.messages.append(self.llm.invoke(state.messages))  # type: ignore[arg-type]
                last_message_content = self._check_content_is_str(
                    state.messages[-1].content  # type: ignore[union-attr]
                )
                patch_regex_matches = self.patch_regex.findall(last_message_content)
                if len(patch_regex_matches) > 0:
                    break

        extracted_patches = [
            self.patch_extractor.extract_patch_from_content(repo_path, match_content)
            for match_content in patch_regex_matches
        ]
        code_diff.add_patches(extracted_patches)

    def _format_failed_patches(self, failed_patches: set[CodeSnippet]) -> str:
        failed_patch_logs: list[str] = []
        for patch in failed_patches:
            failed_patch_log = ""
            if patch.file_path != "" and patch.line_start > 0 and patch.line_end > 0:
                failed_patch_log += (
                    f"{patch.file_path}:{patch.line_start}-{patch.line_end}"
                )
            if patch.content != "":
                failed_patch_log += f"\n{patch.content}"
            if failed_patch_log != "":
                failed_patch_logs.append(failed_patch_log)

        return "\n\n".join(failed_patch_logs)

    def _extract_diff_with_retry(self, state: PatchState) -> None:
        code_diff = CodeDiff()
        self._extract_and_add_patches(state, code_diff, state.repo_path)

        for _ in range(self.max_n_retries):
            if not code_diff.has_failed_patches():
                break
            user_prompt = self.failed_patches_prompt.format(
                failed_patches=self._format_failed_patches(code_diff.failed_patches)
            )
            state.messages.append(HumanMessage(user_prompt))
            state.messages.append(self.llm.invoke(state.messages))  # type: ignore[arg-type]
            self._extract_and_add_patches(state, code_diff, state.repo_path)
        state.diff = code_diff.concatenated_diff
        state.applied_patches = code_diff.applied_patches
