from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from crete.patcher.base_node import BaseNode


class LLMNode(BaseNode):
    def __init__(self, llm: BaseChatModel) -> None:
        self.llm = llm

    def _check_content_is_str(self, content: Any) -> str:
        if not isinstance(content, str):
            raise ValueError(f"Unexpected message content type: {type(content)}")
        return content
