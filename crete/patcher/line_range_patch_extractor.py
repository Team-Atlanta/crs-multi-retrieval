import re
from pathlib import Path

from crete.patcher.base_patch_extractor import BasePatchExtractor
from crete.state.patch_state import CodeSnippet


class LineRangePatchExtractor(BasePatchExtractor):
    """Extracts a patch from XML formatted content with line ranges.

    Example XML format to extract a patch:
    <original_code>
    ```c
    11:int add(int a, int b) {
    12:    return a - b;
    13:}
    ```
    </original_code>
    <code_lines_to_replace>
    path/to/original_file.c:11-13
    </code_lines_to_replace>
    <patched_code>
    ```c
    int add(int a, int b) {
        return a + b;
    }
    ```
    </patched_code>
    """

    original_code_regex = re.compile(
        r"(?:<original_code>)([\s\S]*?)(?:<\/original_code>)"
    )
    code_lines_to_replace_regex = re.compile(
        r"(?:<code_lines_to_replace>)([\s\S]*?)(?:</code_lines_to_replace>)"
    )
    patched_code_regex = re.compile(r"(?:<patched_code>)([\s\S]*?)(?:<\/patched_code>)")

    def __init__(self, n_check_lines: int = 3) -> None:
        super().__init__()
        self.n_check_lines = n_check_lines

    def extract_patch_from_content(self, repo_path: str, content: str) -> CodeSnippet:
        code_snippet = CodeSnippet()
        code_lines_to_replace_match = self.code_lines_to_replace_regex.search(content)
        patched_code_match = self.patched_code_regex.search(content)
        if code_lines_to_replace_match is None or patched_code_match is None:
            return code_snippet
        file_path_and_lines = code_lines_to_replace_match.group(1).strip()
        try:
            file_path, lines = file_path_and_lines.split(":", 1)
            if "-" in lines:
                line_start, line_end = lines.split("-", 1)
                line_start_int, line_end_int = int(line_start), int(line_end)
            else:
                line_start_int = int(lines)
                line_end_int = line_start_int
        except ValueError:
            return code_snippet
        except IndexError:
            return code_snippet

        rebased_file_path = self.rebase_file_path(repo_path, file_path)
        if rebased_file_path is None:
            return code_snippet

        patched_code = self.extract_code_from_markdown(patched_code_match.group(1))
        code_snippet = CodeSnippet(
            repo_path=repo_path,
            file_path=rebased_file_path,
            line_start=line_start_int,
            line_end=line_end_int,
            content=patched_code,
        )

        original_code_match = self.original_code_regex.search(content)
        if original_code_match is not None:
            original_code = self.extract_code_from_markdown(
                original_code_match.group(1)
            )
            code_snippet = self._adjust_line_range_from_original_code(
                code_snippet, original_code
            )
        return code_snippet

    def _adjust_line_range_from_original_code(
        self, code_snippet: CodeSnippet, original_code: str
    ) -> CodeSnippet:
        orig_code_lines = original_code.split("\n")
        if len(orig_code_lines) > 0 and orig_code_lines[-1] == "":
            orig_code_lines = orig_code_lines[:-1]
        if all(":" in line for line in orig_code_lines):
            orig_code_lines = [line.split(":", 1)[1] for line in orig_code_lines]

        if len(orig_code_lines) > 0:
            code_snippet = self._adjust_line_from_original_code(
                code_snippet,
                orig_code_lines[0],
                is_line_start=True,
                strip_code=False,
            )
            code_snippet = self._adjust_line_from_original_code(
                code_snippet,
                orig_code_lines[-1],
                is_line_start=False,
                strip_code=False,
            )
            code_snippet = self._adjust_line_from_original_code(
                code_snippet,
                orig_code_lines[0],
                is_line_start=True,
                strip_code=True,
            )
            code_snippet = self._adjust_line_from_original_code(
                code_snippet,
                orig_code_lines[-1],
                is_line_start=False,
                strip_code=True,
            )
        return code_snippet

    def _adjust_line_from_original_code(
        self,
        code_snippet: CodeSnippet,
        code_line_to_check: str,
        *,
        is_line_start: bool = True,
        strip_code: bool = False,
    ) -> CodeSnippet:
        if strip_code:
            code_line_to_check = code_line_to_check.strip()
        if code_line_to_check == "":
            return code_snippet

        abs_file_path = Path(code_snippet.repo_path) / code_snippet.file_path
        if not abs_file_path.exists() or not abs_file_path.is_file():
            return code_snippet
        full_code_lines = abs_file_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines(keepends=True)

        line_number_diff_to_check = [0]
        for idx in range(1, self.n_check_lines + 1):
            line_number_diff_to_check.extend([idx, -idx])

        if is_line_start:
            target_line_number = code_snippet.line_start
        else:
            target_line_number = code_snippet.line_end

        for line_number_diff in line_number_diff_to_check:
            line_idx_to_check = target_line_number + line_number_diff - 1
            if line_idx_to_check < 0 or line_idx_to_check >= len(full_code_lines):
                continue
            line_from_file = full_code_lines[line_idx_to_check]
            if len(line_from_file) > 0 and line_from_file[-1] == "\n":
                line_from_file = line_from_file[:-1]

            if strip_code:
                line_from_file = line_from_file.strip()
            if line_from_file == "":
                continue
            if line_from_file == code_line_to_check:
                if is_line_start:
                    code_snippet.line_start = line_idx_to_check + 1
                else:
                    code_snippet.line_end = line_idx_to_check + 1
                break
        return code_snippet
