"""guarded-llm-gateway: a FastAPI gateway that guards a bank support assistant."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("guarded-llm-gateway")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"
