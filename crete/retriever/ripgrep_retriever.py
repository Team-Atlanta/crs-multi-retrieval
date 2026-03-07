import shutil
import subprocess
from pathlib import Path

from crete.retriever.base_retriever import BaseRetriever
from crete.state.retrieval_state import (
    RetrievalCategory,
    RetrievalPriority,
    RetrievalQuery,
    RetrievalResult,
)


class RipgrepRetriever(BaseRetriever):
    def __init__(
        self,
        n_context_lines: int = 5,
        max_n_results_per_query: int = 8,
        retrieval_priority: RetrievalPriority = RetrievalPriority.LOW,
    ):
        super().__init__(
            query_category=RetrievalCategory.CODE_SNIPPET,
            max_n_results_per_query=max_n_results_per_query,
        )
        self.n_context_lines = n_context_lines
        self.max_n_results_per_query = max_n_results_per_query
        self.retrieval_priority = retrieval_priority

        rg_path = shutil.which("rg")
        if rg_path is None:
            raise FileNotFoundError("Ripgrep binary not found. Please install ripgrep.")
        self._rg_executable = Path(rg_path)

    def _retrieve(self, query: RetrievalQuery) -> list[RetrievalResult]:
        if query.query is None or query.query == "":
            return []
        if query.repo_path is None or query.repo_path == "":
            return []

        log = self._run_ripgrep(query.query, query.repo_path)
        if log == "":
            return []

        results: list[RetrievalResult] = []
        for search_result in log.split("\n\n"):
            if "\n" not in search_result:
                continue
            full_file_path, code = search_result.split("\n", maxsplit=1)
            file_path = str(Path(full_file_path).relative_to(query.repo_path))
            code_lines = code.split("\n")
            line_start = 0
            for line in code_lines:
                try:
                    line_start = int(line.split(":", maxsplit=1)[0])
                    break
                except ValueError:
                    pass

            line_end = 0
            for line in reversed(code_lines):
                try:
                    line_end = int(line.split(":", maxsplit=1)[0])
                    break
                except ValueError:
                    pass
            result = RetrievalResult(
                content=code,
                file_path=file_path,
                file_lang="",
                line_start=line_start,
                line_end=line_end,
                priority=self.retrieval_priority,
            )
            result.update_from_query(query)
            results.append(result)
        return results

    def _run_ripgrep(self, query: str, repo_path: str) -> str:
        rg_command = [
            str(self._rg_executable),
            f"--context={self.n_context_lines}",
            "--line-number",
            "--heading",
            "--context-separator=...",
            "--field-context-separator=:",
            "--color=never",
            query,
            repo_path,
        ]
        result = subprocess.run(rg_command, capture_output=True, check=False)
        return result.stdout.decode("utf-8", errors="replace")
