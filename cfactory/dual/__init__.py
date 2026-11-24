"""验收状态与策略（供 Agent-only verify 使用）。"""
from .strategy import (
    STATUS_ENV_READY, STATUS_FAILED, STATUS_FAST_VERIFIED,
    STATUS_ROBUST_VERIFIED, STATUS_UNSUPPORTED,
    DualResult, get_strategy, robust_strategy, fast_strategy,
)

__all__ = [
    "DualResult", "get_strategy", "robust_strategy", "fast_strategy",
    "STATUS_ROBUST_VERIFIED", "STATUS_FAST_VERIFIED", "STATUS_ENV_READY",
    "STATUS_UNSUPPORTED", "STATUS_FAILED",
]
