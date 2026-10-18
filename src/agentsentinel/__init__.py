"""AgentSentinel — deterministic, sandboxed, evidence-first automated software repair engine."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("agentsentinel")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0+dev"

__all__ = ["__version__"]
