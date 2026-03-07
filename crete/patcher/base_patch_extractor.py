from abc import ABC, abstractmethod
from pathlib import Path

from crete.state.patch_state import CodeSnippet


class BasePatchExtractor(ABC):
    @abstractmethod
    def extract_patch_from_content(self, repo_path: str, content: str) -> CodeSnippet:
        pass

    def extract_code_from_markdown(self, markdown_code: str) -> str:
        stripped_code = markdown_code.strip()
        if stripped_code.startswith("```") and stripped_code.endswith("```"):
            markdown_code = stripped_code.split("\n", maxsplit=1)[1][:-3]
        else:
            if markdown_code.startswith("\n"):
                markdown_code = markdown_code[1:]
            if markdown_code.endswith("\n"):
                markdown_code = markdown_code[:-1]
        return markdown_code

    def rebase_file_path(self, repo_path: str, relative_file_path: str) -> str | None:
        relative_parts = Path(relative_file_path).parts
        rebased_file_path = None
        for idx in range(len(relative_parts)):
            curr_path = str(Path(*relative_parts[idx:]))
            check_path = Path(repo_path) / curr_path
            if check_path.exists() and check_path.is_file():
                rebased_file_path = curr_path
                break
        return rebased_file_path
