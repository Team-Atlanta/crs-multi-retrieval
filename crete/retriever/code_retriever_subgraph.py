import inspect
import re

from langgraph.graph import END, START, StateGraph

from crete.retriever.ast_grep_retriever import ASTGrepRetriever
from crete.retriever.file_retriever import FileRetriever
from crete.state.retrieval_state import (
    RetrievalCategory,
    RetrievalPriority,
    RetrievalQuery,
    RetrievalResult,
    RetrievalState,
)


class CodeRetrieverSubgraph:
    retrieved_code_prompt = inspect.cleandoc(
        """
        {file_path}:{line_start}-{line_end}
        ```{lang}
        {code}
        ```
        """
    )
    retrieval_not_found_prompt = inspect.cleandoc(
        """
        Search failed with the requested query.
        Please, do not request with the same query without modification.
        Possible reasons are:
        - The query format is incorrect.
        - The code or file does not exist in the codebase.
        - The code is an external library or a system library that cannot be reached.
        """
    )
    retrieval_prompt = inspect.cleandoc(
        """
        <retrieved>
        {query}
        <code>
        {code}
        </code>
        </retrieved>
        """
    )
    grep_query_regex = re.compile(r"(?:<grep>)([\s\S]*?)(?:<\/grep>)")
    file_query_regex = re.compile(r"(?:<file>)([\s\S]*?)(?:<\/file>)")

    def __init__(
        self,
        max_retrievals_per_query: int = 16,
        *,
        add_line_numbers: bool = True,
    ):
        self.max_retrievals_per_query = max_retrievals_per_query

        self._ast_grep_retriever = ASTGrepRetriever(
            add_line_numbers=add_line_numbers,
            whold_word_retrieval_priority=RetrievalPriority.HIGH,
            partial_word_retrieval_priority=RetrievalPriority.MEDIUM,
        )
        self._file_retriever = FileRetriever(
            add_line_numbers=add_line_numbers,
            retrieval_priority=RetrievalPriority.LOW,
        )

        self._subgraph_builder = StateGraph(RetrievalState)
        self._subgraph_builder.add_node("ast_grep_retriever", self._ast_grep_retriever)  # type: ignore[arg-type]
        self._subgraph_builder.add_node("file_retriever", self._file_retriever)  # type: ignore[arg-type]
        self._subgraph_builder.add_node(  # type: ignore[arg-type]
            "aggregate_retrievals", self._aggregate_retrievals
        )
        self._subgraph_builder.add_edge(START, "ast_grep_retriever")
        self._subgraph_builder.add_edge(START, "file_retriever")
        self._subgraph_builder.add_edge(
            ["ast_grep_retriever", "file_retriever"], "aggregate_retrievals"
        )
        self._subgraph_builder.add_edge("aggregate_retrievals", END)
        self._compiled_subgraph = self._subgraph_builder.compile()  # type: ignore[var-annotated]

    def retrieve_from_content(self, content: str, repo_path: str) -> str:
        initial_retrieval_state = self._init_retrieval_state(content, repo_path)
        retrieval_state = RetrievalState(
            **self._compiled_subgraph.invoke(initial_retrieval_state)
        )
        retrieved_code = self._format_retrievals(retrieval_state)
        return retrieved_code

    def _aggregate_retrievals(
        self, retrieval_state: RetrievalState
    ) -> dict[str, list[RetrievalResult] | list[RetrievalQuery]]:
        query_to_retrievals: dict[str, set[RetrievalResult]] = {}
        for result in retrieval_state.results:
            if result.query is None:
                continue
            if result.query not in query_to_retrievals:
                query_to_retrievals[result.query] = set()
            query_to_retrievals[result.query].add(result)

        for query, retrieval_results in query_to_retrievals.items():
            sorted_retrieval_results = sorted(
                retrieval_results, key=lambda x: x.priority, reverse=True
            )[: self.max_retrievals_per_query]
            query_to_retrievals[query] = {
                result
                for result in sorted_retrieval_results
                if result.priority == sorted_retrieval_results[0].priority
            }

        reranked_results: list[RetrievalResult] = []
        for retrieval_results in query_to_retrievals.values():
            reranked_results.extend(retrieval_results)

        not_found_queries: dict[str, RetrievalQuery] = {}
        for retrieval_query in retrieval_state.queries:
            if retrieval_query.query is None:
                continue
            if retrieval_query.query not in query_to_retrievals:
                if retrieval_query.query not in not_found_queries:
                    not_found_queries[retrieval_query.query] = retrieval_query
        return {
            "reranked": reranked_results,
            "not_found": list(not_found_queries.values()),
        }

    def _init_retrieval_state(self, content: str, repo_path: str) -> RetrievalState:
        grep_queries = self.grep_query_regex.findall(content)

        retrieval_queries: list[RetrievalQuery] = []
        for query in grep_queries:
            retrieval_queries.append(
                RetrievalQuery(
                    query=query,
                    repo_path=repo_path,
                    category=RetrievalCategory.CODE_SNIPPET,
                )
            )

        file_queries = self.file_query_regex.findall(content)
        for query in file_queries:
            retrieval_queries.append(
                RetrievalQuery(
                    query=query,
                    repo_path=repo_path,
                    category=RetrievalCategory.FILE,
                )
            )
        return RetrievalState(queries=retrieval_queries)

    def _format_retrievals(self, retrieval_state: RetrievalState) -> str:
        query_to_retrievals: dict[str, list[RetrievalResult]] = {}
        for result in retrieval_state.reranked:
            if result.query is None:
                continue
            if result.query not in query_to_retrievals:
                query_to_retrievals[result.query] = []
            query_to_retrievals[result.query].append(result)

        formatted_retrievals: list[str] = []
        for query, retrieval_results in query_to_retrievals.items():
            retrieved_codes: list[str] = []
            for result in retrieval_results:
                if result.content is None:
                    continue
                code = result.content
                if code.endswith("\n"):
                    code = code[:-1]
                retrieved_codes.append(
                    self.retrieved_code_prompt.format(
                        file_path=result.file_path,
                        line_start=result.line_start,
                        line_end=result.line_end,
                        lang=result.file_lang,
                        code=code,
                    )
                )
            formatted_retrievals.append(
                self.retrieval_prompt.format(
                    query=query,
                    code="\n---\n".join(retrieved_codes),
                )
            )

        for retrieval_query in retrieval_state.not_found:
            formatted_retrievals.append(
                self.retrieval_prompt.format(
                    query=retrieval_query.query,
                    code=self.retrieval_not_found_prompt,
                )
            )
        return "\n".join(formatted_retrievals)
