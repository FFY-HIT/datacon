from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PoC:
    code: str
    language: str = "python"
    filename: str = "poc.py"
    markers: list[str] = field(default_factory=list)
    mode: str = "synthesize"
    attempt: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    backend: str = ""
    image: str = ""

    def combined(self) -> str:
        return (self.stdout or "") + "\n" + (self.stderr or "")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verification:
    passed: bool = False
    confidence: float = 0.0
    layer: str = ""
    state_tag: str = ""
    evidence: list[str] = field(default_factory=list)
    reasoning: str = ""
    llm_invoked: bool = False
    differential_passed: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PocLoopResult:
    success: bool = False
    triggered: bool = False
    differential_passed: bool | None = None
    final_layer: str = ""
    iterations: int = 0
    strategic_cycles: int = 0
    routes: list[str] = field(default_factory=list)
    failure_reason: str = ""
    best_poc: dict[str, Any] = field(default_factory=dict)
    trace: list[dict[str, Any]] = field(default_factory=list)
    proof: str = ""
    elapsed: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
