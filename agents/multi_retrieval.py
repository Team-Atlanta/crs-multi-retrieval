"""Multi-retrieval agent for autonomous vulnerability patching.

Implements the agent interface (setup / run) using the crete framework's
MultiRetrievalPatchAgent with a LangGraph-based patch workflow.
Replaces LlmApiManager with direct ChatLiteLLM instantiation.

Docker-only dependencies (langchain_community, libCRS, crete.agent) are
imported lazily inside functions so the module can be imported for testing
without those packages installed.
"""

import logging
import os
from pathlib import Path
from typing import Any

from crete.analyzer.jvm_stackoverflow import JVMStackOverflowStacktraceAnalyzer
from crete.analyzer.jvm_timeout import JVMTimeoutStacktraceAnalyzer
from crete.atoms.action import Action, choose_best_action, get_score
from crete.atoms.detection import AIxCCChallengeDeltaMode, BlobInfo, Detection
from crete.environment.environment_pool import EnvironmentPool
from crete.evaluator.default_evaluator import DefaultEvaluator

logger = logging.getLogger(__name__)

# Language mapping: oss-crs language strings → crete Language literals
_LANGUAGE_MAP: dict[str, str] = {
    "c": "c",
    "c++": "cpp",
    "cpp": "cpp",
    "jvm": "jvm",
    "java": "jvm",
}

# Module-level state set by setup()
_primary_llm: Any = None
_backup_llm: Any = None


def setup(source_dir: Path, config: dict[str, str]) -> None:
    """One-time agent configuration.

    Reads LLM API URL/key from config dict and model names from env.
    Configures LiteLLM environment variables and instantiates ChatLiteLLM
    instances for primary and backup models.
    """
    global _primary_llm, _backup_llm

    from langchain_community.chat_models import ChatLiteLLM

    llm_api_url = config.get("llm_api_url", "")
    llm_api_key = config.get("llm_api_key", "")

    # Configure env vars for litellm's OpenAI provider. The openai/ prefix on
    # model names tells litellm to use the OpenAI SDK, which reads OPENAI_API_BASE
    # and OPENAI_API_KEY to determine the endpoint. ChatLiteLLM's constructor
    # params (openai_api_base/openai_api_key) are NOT forwarded to litellm's
    # completion() call in the deprecated langchain_community version, so env
    # vars are the reliable way to route through the proxy.
    os.environ["OPENAI_API_BASE"] = llm_api_url
    os.environ["OPENAI_API_KEY"] = llm_api_key

    # Read model names from environment (with defaults)
    primary_model = os.environ.get("MULTI_RETRIEVAL_MODEL", "o4-mini")
    backup_model = os.environ.get("MULTI_RETRIEVAL_BACKUP_MODEL", "gemini-2.5-pro")

    # The "openai/" prefix tells litellm to use the OpenAI-compatible protocol,
    # routing through OPENAI_API_BASE. The proxy strips the prefix.
    _primary_llm = ChatLiteLLM(model=f"openai/{primary_model}")
    _backup_llm = ChatLiteLLM(model=f"openai/{backup_model}")

    logger.info(
        "Multi-retrieval agent configured: primary=%s, backup=%s, api_base=%s",
        primary_model,
        backup_model,
        llm_api_url,
    )


def run(
    source_dir: Path,
    povs: list[tuple[Path, str]],
    harness: str,
    patches_dir: Path,
    work_dir: Path,
    *,
    language: str = "c",
    sanitizer: str = "address",
    builder: str,
    ref_diff: str | None = None,
) -> bool:
    """Run the multi-retrieval agent to fix a vulnerability.

    1. Creates libCRS-backed environment with builder sidecar
    2. Builds Detection from POV files
    3. Invokes MultiRetrievalPatchAgent.act() to run the LangGraph workflow
    4. Extracts best patch and writes to patches_dir/patch_001.diff

    Returns True if a patch was produced.
    """
    from crete.agent.multi_retrieval_agent import MultiRetrievalPatchAgent
    from libCRS.cli.main import init_crs_utils

    crs = init_crs_utils()

    # Create environment pool
    pool = EnvironmentPool(
        crs=crs,
        builder=builder,
        source_directory=source_dir,
    )

    # Build Detection from POV files
    crete_language = _LANGUAGE_MAP.get(language, language)
    blobs = [
        BlobInfo(
            harness_name=harness,
            sanitizer_name=sanitizer,
            blob=pov_path.read_bytes(),
        )
        for pov_path, _crash_log in povs
    ]

    # Determine challenge mode
    mode = None
    if ref_diff is not None:
        mode = AIxCCChallengeDeltaMode(
            base_ref="HEAD",
            delta_ref="HEAD~1",
        )

    detection = Detection(
        mode=mode,
        vulnerability_identifier=harness,
        project_name=os.environ.get("OSS_CRS_TARGET", source_dir.name),
        language=crete_language,
        blobs=blobs,
        sarif_report=None,
    )

    # Build agent context
    evaluator = DefaultEvaluator(
        pool=pool,
        response_dir=work_dir / "eval_response",
    )

    context: dict[str, object] = {
        "pool": pool,
        "evaluator": evaluator,
        "output_directory": work_dir / "output",
        "jvm_timeout_analyzer": JVMTimeoutStacktraceAnalyzer(),
        "jvm_stackoverflow_analyzer": JVMStackOverflowStacktraceAnalyzer(),
    }

    # Create and run agent
    agent = MultiRetrievalPatchAgent(
        llm=_primary_llm,
        backup_llm=_backup_llm,
        recursion_limit=256,
        max_n_evals=16,
    )

    try:
        actions = list(agent.act(context, detection))
    except Exception:
        logger.exception("Agent failed during execution")
        return False

    if not actions:
        logger.warning("Agent produced no actions")
        return False

    # Pick the best action
    best_action = choose_best_action(actions)
    logger.info(
        "Best action: %s (score=%d)",
        type(best_action).__name__,
        get_score(best_action),
    )

    # Extract diff from best action
    if not _has_diff(best_action):
        logger.info("Best action has no diff — no patch produced")
        return False

    diff_bytes = best_action.diff  # type: ignore[union-attr]
    patches_dir.mkdir(parents=True, exist_ok=True)
    patch_path = patches_dir / "patch_001.diff"
    patch_path.write_bytes(diff_bytes)
    logger.info("Patch written to %s (%d bytes)", patch_path, len(diff_bytes))

    return True


def _has_diff(action: Action) -> bool:
    """Check if an action carries a diff payload."""
    return hasattr(action, "diff") and action.diff is not None  # type: ignore[union-attr]
