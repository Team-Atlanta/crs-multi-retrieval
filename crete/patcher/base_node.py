from typing import Any, Protocol


class BaseNode(Protocol):
    def __call__(self, state: Any) -> dict[str, Any]: ...
