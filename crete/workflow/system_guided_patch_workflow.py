import logging
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.runnables.config import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from crete.agent.context import AgentContext
from crete.atoms.detection import Detection
from crete.evaluator.docker_evaluator import DockerEvaluator
from crete.patcher.system_guided_patcher import SystemGuidedPatcher
from crete.state.patch_state import PatchAction, PatchState

logger = logging.getLogger(__name__)


class SystemGuidedPatchWorkflow:
    """LangGraph StateGraph workflow: START → docker_evaluator → router → [retrieval_patcher | DONE]."""

    def __init__(self, *, max_n_evals: int = 5) -> None:
        self.max_n_evals = max_n_evals
        self.graph_builder = StateGraph(PatchState)
        self.docker_evaluator: DockerEvaluator | None = None
        self.retrieval_patcher: SystemGuidedPatcher | None = None
        self._compiled_graph: CompiledStateGraph | None = None

    @property
    def compiled_graph(self) -> CompiledStateGraph:
        if self._compiled_graph is None:
            raise ValueError("Workflow is not compiled. Please call compile() first.")
        return self._compiled_graph

    def compile(self, llm: BaseChatModel) -> None:
        self.docker_evaluator = DockerEvaluator(max_n_evals=self.max_n_evals)
        self.retrieval_patcher = SystemGuidedPatcher(llm=llm, max_n_retries=0)

        self.graph_builder.add_node("docker_evaluator", self.docker_evaluator)  # type: ignore[arg-type]
        self.graph_builder.add_node("retrieval_patcher", self.retrieval_patcher)  # type: ignore[arg-type]
        self.graph_builder.add_node("router", self.router_node)  # type: ignore[arg-type]

        self.graph_builder.add_edge(START, "docker_evaluator")
        self.graph_builder.add_edge("docker_evaluator", "router")
        self.graph_builder.add_edge("retrieval_patcher", "router")
        self.graph_builder.add_conditional_edges("router", self.router_function)

        self._compiled_graph = self.graph_builder.compile()  # type: ignore[assignment]

    def invoke(self, state: PatchState, config: RunnableConfig) -> dict[str, Any] | Any:
        state.patch_action = PatchAction.EVALUATE
        return self.compiled_graph.invoke(state, config)

    def update(self, context: AgentContext, detection: Detection) -> None:
        if self.docker_evaluator is None:
            raise ValueError(
                "DockerEvaluator is not initialized. Please call compile() first."
            )
        self.docker_evaluator.set_context_and_detection(context, detection)

    def set_llm(self, llm: BaseChatModel) -> None:
        if self.retrieval_patcher is None:
            raise ValueError(
                "RetrievalPatcher is not initialized. Please call compile() first."
            )
        self.retrieval_patcher.llm = llm

    def router_node(self, state: PatchState) -> dict[str, Any]:
        logger.info(
            "SystemGuidedPatchWorkflow Routing:\n%s, %s",
            state.patch_action,
            state.patch_status,
        )
        return {"patch_action": state.patch_action}

    def router_function(self, state: PatchState) -> str:
        if state.patch_action in (PatchAction.ANALYZE_ISSUE, PatchAction.RETRIEVE):
            return "retrieval_patcher"
        if state.patch_action == PatchAction.EVALUATE:
            return "docker_evaluator"
        if state.patch_action == PatchAction.DONE:
            return END
        return END
