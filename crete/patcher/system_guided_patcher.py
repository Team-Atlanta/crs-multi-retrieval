import inspect
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from crete.patcher.base_patcher import BasePatcher
from crete.retriever.code_retriever_subgraph import CodeRetrieverSubgraph
from crete.state.patch_state import PatchAction, PatchState


class SystemGuidedPatcher(BasePatcher):
    system_prompt: str = inspect.cleandoc(
        """\
        Your task is to resolve the given software issue by taking multiple rounds of interactions with the codebase.
        Each interaction involves analyzing the issue, generating an exploration plan, and choosing the action to take.
        ---
        ### Interaction Steps
        Below are the steps to follow for each interaction.

        Step 1: Analyze the Issue
        - Provide a brief summary of the current state of the issue.
        - Identify the possible root causes of the issue.
        - List the affected components of the codebase.
        - Suggest multiple different approaches to resolve the issue.
        - Mention the possible side effects of the suggested approaches.
        - Fuzzer output logs can be provided as a issue.
        - Avoid solutions that changes the fuzzer and harness code itself or system code.
        - If previous patches have failed, suggest alternative approaches.
        - If previous patches introduced regressions, suggest other minimal approaches.
        - Provide the analysis inside the <analysis> and </analysis> tags.

        Step 2: Generate an Exploration Plan
        - Identify the core logics, functions, or codebase specific constants related to the issue.
        - Explore other parts of the codebase that may lead to the root causes.
        - Identify similar logics or functions that are working correctly.
        - Explore the codebase to reduce the risk of software regression before patching.
        - List what to explore next from the latest exploration to reach the root causes.
        - Provide the exploration plan inside the <exploration_plan> and </exploration_plan> tags.

        Step 3: Choose an Action to Take between Retrieving the Source Code or Submitting Generated Patches
        - Always retrieve codes multiple times before submitting the patches.
        - Always try to explore deeper into the codebase to find related contexts.
        - Even if patching seems straightforward, explore other possible fix locations.
        - If you choose to retrieve the source code, provide the retrieval queries inside the <retrievals> and </retrievals> tags.
        - If you choose to submit the generated patches, provide all the patches needed inside the <patches> and </patches> tags.
        - Adhere the detailed instructions below to choose the action.
        ---
        ### Detailed Instructions for Actions
        Below are the detailed instructions for actions you can take.

        Action 1: Retrieve the Source Code
        - You can retrieve only from the original codebase by providing the retrieval queries inside the <retrievals> and </retrievals> tags.
        - The types of retrieval queries are as follows:
          a) Querying with <grep> and </grep> tags.
            - This retrieves exact matches of the query from the codebase.
            - This can retrieve definitions or line surroudings of the query.
            - Class names, function names, variable names, type names, or one-line code can be queried.
          b) Querying with <file> and </file> tags.
            - This retrieves the file content using the requested file path or name.
            - Add line ranges to retrieve specific parts of the file content.
        - The rules for requesting retrieval queries are as follows:
          - At least 3 queries are required.
          - You can request multiple retrieval queries up to 5.
          - Try only with grep queries first, and then file queries if necessary.
          - Limit the number of file queries to 1.
          - Refrain from requesting too generic queries that may result in irrelevant code.
          - Prefer to use the fully qualified class name and class method name for reducing ambiguity.
        - Examples of valid grep queries:
        <retrievals>
        <grep>example.using.fully.qualified.ClassName</grep>
        <grep>function_name</grep>
        <grep>example.using.fully.qualified.ClassName.methodName</grep>
        <grep>variable_type_name</grep>
        <grep>one_line_code</grep>
        </retrievals>
        - Examples of valid file queries:
        <retrievals>
        <file>relative/path/to/file_name.py</file>
        <file>relative/path/to/file_name.py:20-30</file>
        </retrievals>

        Action 2: Submit Generated Patches
        - You can submit patches by generating all the patches needed inside the <patches> and </patches> tags.
        - Here are the steps to follow for generating the patches:
          a) Enclose each patch inside <patch> and </patch> tags.
          b) Copy the original code to replace from the retrieved code between <original_code> and </original_code> tags.
            - The original code must be a unique code that can be replaced by the generated patch.
            - Copy the exact line numbers, indentations, white spaces, and newlines of the original code to successfully replace it.
            - Try to copy multiple lines of code to replace with context.
            - Do NOT abbreviate the original code.
            - No overlapping original code lines are allowed when providing multiple patches.
          c) Copy the file path and code line range to replace between <code_lines_to_replace> and </code_lines_to_replace> tags.
            - The line range should be in the format of "path/to/file.py:line_start-line_end".
            - Copy the first line number of the original code to replace as line_start.
            - Copy the last line number of the original code to replace as line_end.
            - Do NOT estimate the line numbers.
            - Do NOT copy only the new line character as the start or end line itself. (White spaces with code are allowed.)
            - No overlapping line range are allowed when providing multiple patches. (e.g. 1-5, 6-10 is allowed, but 1-5, 5-10 is not allowed)
          d) Generate a patched code that can replace the copied original code inside <patched_code> and </patched_code> tags.
            - The patched code must successfully replace the original code without compilation errors.
            - The patched code must not alter existing core logic of the codebase.
            - Follow the same indentation level of the original code exactly in the patched code.
            - Do NOT try to replace a omitted or abbreviated code.
            - Do NOT try to abbreviate in the patched code.
            - Do NOT write line numbers in the patched code.
            - Do NOT generate an empty patched code. (In case of only removing the code, try to replace it with a comment.)
            - Do NOT generate additional comments in the patched code.
          e) Repeat the process for each patch to provide multiple patches for multiple line ranges.
            - You must provide all the patches needed to address the issue. (The patch is always applied to the initial codebase.)
            - If multiple functions or classes are needed to be patched, try to split them into separate non-overlapping patches.
            - Since previous patches are not applied, provide all the patches needed to address the issue or multiple issues.
            - If the previous patches must be applied before the current patch, provide those again.
            - If incrementailly solving multiple issues, do not forget to provide all the patches including the previous ones.
            - Do not forget to patch the import statements when additional imports are needed.
        - Beware to not indent any of the tags itself.
        - Example of a single patch generation exactly replacing the code:
        <code>
        path/to/original_file.c:10-18
        ```c
        10:
        11:int add(int a, int b) {
        12:    return a - b;
        13:}
        14:
        15:int sub(int a, int b) {
        16:    return a - b;
        17:}
        18:
        ```
        </code>
        For the above example, a valid patch with exact line ranges is as follows:
        <patches>
        <patch>
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
        </patch>
        </patches>

        - Example of a multiple patch generation:
        <patches>
        <patch>
        <original_code>
        ```python
        111:    def class_method(self):
        112:        # multiple lines of
        113:        # original code for the issue
        114:        return
        ```
        </original_code>
        <code_lines_to_replace>
        path/to/original_file_1.py:111-114
        </code_lines_to_replace>
        <patched_code>
        ```python
            def class_method(self):
                # multiple lines of
                # patched code for the issue
                return
        ```
        </patched_code>
        </patch>
        <patch>
        <original_code>
        ```python
        333:def another_method(self):
        334:    # multiple lines of
        335:    # original code for the issue
        ```
        </original_code>
        <code_lines_to_replace>
        path/to/original_file_2.py:333-335
        </code_lines_to_replace>
        <patched_code>
        ```python
        def another_method():
            # patched code for
            # previous issue or
            # another location
        ```
        </patched_code>
        </patch>
        </patches>
        ---
        ### Example Interactions
        Below are the whole templates to follow for each case of interaction.

        Case 1: Choosing to retrieve the source code after analysis and planning
        <analysis>
        ...
        </analysis>
        <exploration_plan>
        ...
        </exploration_plan>
        <retrievals>
        ...
        </retrievals>

        Case 2: Choosing to submit generated patches after analysis and planning
        <analysis>
        ...
        </analysis>
        <exploration_plan>
        ...
        </exploration_plan>
        <patches>
        <patch>
        ...
        </patch>
        </patches>

        Follow the above templates exactly for each case of interaction.
        ---
        ### Important Notes while Interacting
        - Remember to explore multiple layers of the codebase to find the real root causes of the issue other than just the symptoms.
        - Always provide the analysis, exploration plan, and the choice of action in the specified tags.
        - Flexible and creative different types of approaches are encouraged when the issue persists.
        - If the same issue persists, try to explore other approaches for different parts of the codebase.
        - Do NOT iterate with the similar solutions. Try completely different approaches if possible.

        ## Important Notes for Patching
        - Try to provide all the patches needed to patch from the initial codebase.
        - The harness code is not the root cause and it serves as an entry point for the fuzzer to test the codebase.
        - The fuzzing can be done by some APIs which are not the root cause of the issue. It is just a way to trigger the issue in the codebase.
        - Do NOT fix fuzzing logic or harness code related files, functions, definitions, macros, or flags to bypass the issue. (Usually include words like "fuzz", "harness", "test", etc.)
        - If additional issue is reported only in the harness code, this means that the last patch attempt did not resolve the issue correctly.
        - Modifying the fuzzing logic or harness code is strictly prohibited. They are the tests to be passed by fixing the codebase.
        - Do NOT modify or fix any test codes. The patched code must not break the existing tests and functionalities.
        - Do not remove a functionality to bypass the issue. Removal only patch is only allowed for mallicious code.
        - Do NOT modify error handling code to catch too broad exceptions.
        """
    )
    initial_issue_prompt: str = inspect.cleandoc(
        """\
        Here is the initial issue of the codebase:
        <issue>
        {issue}
        </issue>
        """
    )
    feedback_issue_prompt: str = inspect.cleandoc(
        """\
        Your last patch attempt failed to resolve the issue or introduced regressions.
        Here is the issue after the last patch attempt:
        <issue>
        {issue}
        </issue>
        """
    )

    retrieved_prompt: str = inspect.cleandoc(
        """\
        {retrieved}
        """
    )
    retry_prompt: str = inspect.cleandoc(
        """\
        Parsing failed. Please generate the response in the correct format.
        You must provide <retrievals> and <retrievals> tags or <patches> and <patches> tags.
        """
    )

    def __init__(
        self,
        llm: BaseChatModel,
        max_n_retries: int = 3,
        max_retrievals_per_query: int = 16,
        *,
        add_line_numbers: bool = True,
    ) -> None:
        super().__init__(llm, max_n_retries=max_n_retries)
        self.code_retriever_subgraph = CodeRetrieverSubgraph(
            max_retrievals_per_query=max_retrievals_per_query,
            add_line_numbers=add_line_numbers,
        )

    def __call__(self, state: PatchState) -> dict[str, Any]:
        if state.patch_action == PatchAction.ANALYZE_ISSUE:
            if state.issue is None:
                raise ValueError("Issue not provided.")

            if len(state.messages) == 0:
                state.messages.append(SystemMessage(self.system_prompt))
                state.messages.append(
                    HumanMessage(self.initial_issue_prompt.format(issue=state.issue))
                )
            else:
                state.messages.append(
                    HumanMessage(self.feedback_issue_prompt.format(issue=state.issue))
                )

            state.messages.append(self.llm.invoke(state.messages))  # type: ignore[arg-type]
            state.patch_action = PatchAction.RETRIEVE
        elif state.patch_action == PatchAction.RETRIEVE:
            if len(state.messages) == 0:
                raise ValueError("No messages provided.")

            if state.retrieved is not None:
                state.messages.append(
                    HumanMessage(
                        self.retrieved_prompt.format(retrieved=state.retrieved)
                    )
                )
                state.messages.append(self.llm.invoke(state.messages))  # type: ignore[arg-type]
                state.retrieved = None

            next_step_found = False
            for _ in range(self.max_n_retries + 1):
                content = self._check_content_is_str(
                    state.messages[-1].content  # type: ignore[union-attr]
                )
                last_message_content = content
                if "</analysis>" in content:
                    content = content.split("</analysis>")[1]

                if "</exploration_plan>" in content:
                    content = content.split("</exploration_plan>")[1]

                if "<patches>" in content:
                    state.messages[-1].content = content
                    self._extract_diff_with_retry(state)
                    state.patch_action = PatchAction.EVALUATE
                    next_step_found = True
                elif "<retrievals>" in content:
                    state.retrieved = (
                        self.code_retriever_subgraph.retrieve_from_content(
                            content, state.repo_path
                        )
                    )
                    next_step_found = True

                if next_step_found:
                    state.messages[-1].content = last_message_content
                    break

                state.messages.append(HumanMessage(self.retry_prompt))
                state.messages.append(self.llm.invoke(state.messages))  # type: ignore[arg-type]

            if not next_step_found:
                content = self._check_content_is_str(
                    state.messages[-1].content  # type: ignore[union-attr]
                )
                last_message_content = content
                if "<patches>" in content:
                    state.messages[-1].content = content
                    self._extract_diff_with_retry(state)
                    state.patch_action = PatchAction.EVALUATE
                    next_step_found = True
                elif "<retrievals>" in content:
                    state.retrieved = (
                        self.code_retriever_subgraph.retrieve_from_content(
                            content, state.repo_path
                        )
                    )
                    next_step_found = True

                if next_step_found:
                    state.messages[-1].content = last_message_content
                else:
                    raise ValueError("No next step found after multiple retries.")
        else:
            raise ValueError(f"Unknown patch action: {state.patch_action}")
        return {
            "patch_action": state.patch_action,
            "messages": state.messages,
            "retrieved": state.retrieved,
            "diff": state.diff,
            "applied_patches": state.applied_patches,
        }
