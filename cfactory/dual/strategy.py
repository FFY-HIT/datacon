"""验收深度配置与结果状态（Agent-only）。"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

STATUS_ROBUST_VERIFIED = "ROBUST_VERIFIED"
STATUS_FAST_VERIFIED = "FAST_VERIFIED"
STATUS_ENV_READY = "ENV_READY"
STATUS_UNSUPPORTED = "UNSUPPORTED"
STATUS_FAILED = "FAILED"


@dataclass
class StrategyConfig:
    name: str = "robust"
    budget_seconds: int = 1800
    require_fixed_control: bool = True
    require_repeat: bool = True
    require_clean_rebuild: bool = True
    allow_env_ready_without_trigger: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def robust_strategy() -> StrategyConfig:
    return StrategyConfig(
        name="robust",
        budget_seconds=1800,
        require_fixed_control=True,
        require_repeat=True,
        require_clean_rebuild=True,
    )


def fast_strategy() -> StrategyConfig:
    return StrategyConfig(
        name="fast",
        budget_seconds=600,
        require_fixed_control=False,
        require_repeat=False,
        require_clean_rebuild=False,
        allow_env_ready_without_trigger=True,
    )


def get_strategy(mode: str) -> StrategyConfig:
    m = (mode or "robust").lower().strip()
    if m in ("fast", "极速", "quick", "speed"):
        return fast_strategy()
    return robust_strategy()


@dataclass
class DualResult:
    cve_id: str = ""
    mode: str = "agent:robust"
    status: str = STATUS_FAILED
    knowledge: dict[str, Any] = field(default_factory=dict)
    acceptance: dict[str, Any] = field(default_factory=dict)
    strategy: dict[str, Any] = field(default_factory=dict)
    adapter_kind: str = ""
    factory_result: dict[str, Any] = field(default_factory=dict)
    matrix: dict[str, Any] = field(default_factory=dict)
    evidence_paths: list[str] = field(default_factory=list)
    failure_class: str = ""
    failure_reason: str = ""
    elapsed: float = 0.0
    conclusion: str = ""
    model: str = ""
    iterations: int = 0
    total_tokens: int = 0
    llm_calls: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
