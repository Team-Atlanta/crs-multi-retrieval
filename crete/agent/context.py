"""Agent context type for MultiRetrievalPatchAgent.

The original AgentContext is a deeply nested TypedDict chain:
  AgentContext → InsighterContext → FaultLocalizationContext
    → CrashAnalyzerContext + CodeInspectorContext
    → EvaluatingContext → EnvironmentContext → LoggingContext + CachingContext

We simplify to a plain dict[str, Any] since:
- The concrete types (EnvironmentPool, Evaluator, etc.) come from libCRS
  and are not available at import time
- DockerEvaluator already uses dict[str, Any] for context access
- This keeps the interface flexible during the port

Known context keys used by the agent:
- "pool": EnvironmentPoolProtocol — manages Docker environments
- "evaluator": EvaluatorProtocol — evaluates patches
- "logger": logging.Logger — logging instance
- "output_directory": Path — debug output directory (optional)
"""

from typing import Any

AgentContext = dict[str, Any]
