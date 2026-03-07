from enum import Enum, auto
from operator import add
from typing import Annotated, Any

from pydantic import BaseModel


class RetrievalCategory(Enum):
    FILE = auto()
    CODE_SNIPPET = auto()


class RetrievalPriority(Enum):
    HIGH = 2
    MEDIUM = 1
    LOW = 0

    def __lt__(self, other: Enum) -> bool:
        if self.__class__ is other.__class__:
            return self.value < other.value
        raise ValueError("Cannot compare different types")


class RetrievalQuery(BaseModel):
    query: str | None = None
    repo_path: str | None = None
    category: RetrievalCategory = RetrievalCategory.FILE


class RetrievalResult(RetrievalQuery):
    content: str | None = None
    file_path: str | None = None
    file_lang: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    priority: RetrievalPriority = RetrievalPriority.LOW

    def __eq__(self, value: Any) -> bool:
        if not isinstance(value, RetrievalResult):
            return False
        return (
            self.content == value.content
            and self.file_path == value.file_path
            and self.file_lang == value.file_lang
            and self.line_start == value.line_start
            and self.line_end == value.line_end
            and self.priority == value.priority
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.content,
                self.file_path,
                self.file_lang,
                self.line_start,
                self.line_end,
                self.priority,
            )
        )

    def update_from_query(self, query: RetrievalQuery) -> None:
        self.query = query.query
        self.repo_path = query.repo_path
        self.category = query.category

    def add_line_numbers(self) -> None:
        if self.content is None or self.content == "":
            return
        if self.line_start is None or self.line_end is None:
            return

        content_lines = self.content.split("\n")
        valid_n_lines = self.line_end - self.line_start + 1
        if valid_n_lines != len(content_lines):
            if valid_n_lines + 1 == len(content_lines) and content_lines[-1] == "":
                content_lines.pop()
            elif valid_n_lines == len(content_lines) + 1:
                content_lines.append("")
            else:
                raise ValueError("Line range to line mismatch for adding line numbers")

        self.content = "".join(
            f"{idx + self.line_start}:{line}\n"
            for idx, line in enumerate(content_lines[:valid_n_lines])
        )


class RetrievalState(BaseModel):
    queries: list[RetrievalQuery] = []
    results: Annotated[list[RetrievalResult], add] = []
    reranked: list[RetrievalResult] = []
    not_found: list[RetrievalQuery] = []
