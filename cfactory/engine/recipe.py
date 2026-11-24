"""构建配方：替代 env_spec 成为执行契约（版本/安装/端口/触发）。"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BuildRecipe:
    cve_id: str = ""
    ecosystem: str = "python"          # python|java|ruby|node|php|go|c|unknown
    template_id: str = "python_pip"    # 对应 templates 注册表
    package: str = ""
    product: str = ""
    vuln_version: str = ""
    first_fixed_version: str = ""      # 官方修复边界
    control_version: str = ""          # 实验对照版（可 ≠ first_fixed）
    install_vuln: str = ""             # 如 pip install pkg==1.2.3
    install_fixed: str = ""
    base_image: str = "python:3.11-slim"
    language: str = "python"
    port: int = 18080
    start_cmd: str = "python /task/service.py"
    service_style: str = "stdlib_http"  # stdlib_http|wsgi|library_api|cli|twisted_site
    trigger_kind: str = "http"         # http|library_api|cli
    mechanism: str = ""                # e.g. http_pipeline_reorder；空则推断
    success_marker: str = "VULNERABILITY_TRIGGERED"
    evidence_tokens: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=lambda: ["/"])
    config_notes: list[str] = field(default_factory=list)
    trigger_hint: str = ""
    adapter_kind: str = "package_service"
    kernel_limits: str = ""
    unknowns: list[str] = field(default_factory=list)
    source: str = "llm_extract"        # llm_extract|heuristic|cache|known_cases

    def blocking_ok(self) -> tuple[bool, str]:
        if not self.package or self.package == "unknown":
            return False, "missing package"
        if not self.vuln_version or self.vuln_version == "unknown":
            return False, "missing vuln_version"
        if not self.install_vuln:
            return False, "missing install_vuln"
        if self.adapter_kind == "kernel_special":
            return False, "kernel/special host required"
        return True, ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json(), encoding="utf-8")
        return p

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BuildRecipe":
        known = cls.__dataclass_fields__
        return cls(**{k: v for k, v in d.items() if k in known})
