"""知识包：事实、来源、置信度（两版共用）。

关键：first_fixed_version ≠ control_version；
required_evidence_level ≠ achieved_evidence_level。
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SourcedField:
    value: Any = None
    source_url: str = ""
    accessed_at: str = ""
    confidence: float = 0.0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class KnowledgePack:
    cve_id: str = ""
    product: str = ""
    component: str = ""
    ecosystem: str = ""
    aliases: list[str] = field(default_factory=list)

    # 版本：漏洞选用版 / 官方首修边界 / 实验对照版（三者分离）
    affected_versions: list[str] = field(default_factory=list)
    selected_vuln_version: str = ""
    first_fixed_version: str = ""   # 官方修复边界（公告）
    control_version: str = ""       # 实验对照版（可 ≠ first_fixed）
    fix_commit: str = ""
    patch_diff_url: str = ""
    source_checksum: str = ""
    package_checksum: str = ""

    root_cause: str = ""
    related_functions: list[str] = field(default_factory=list)
    trigger_format: str = ""
    config_prerequisites: list[str] = field(default_factory=list)
    auth_prerequisites: list[str] = field(default_factory=list)
    topology_prerequisites: list[str] = field(default_factory=list)

    os_arch: str = "linux/amd64"
    runtime: str = ""
    base_image: str = ""
    base_image_digest: str = ""
    dependencies: list[str] = field(default_factory=list)
    kernel_limits: str = ""         # Docker 共享宿主内核时的限制说明

    poc_available: bool = False
    poc_verified: bool = False
    poc_refs: list[str] = field(default_factory=list)
    upstream_tests: list[str] = field(default_factory=list)

    # 证据等级：要求 vs 实际达成（不可自动升级）
    required_evidence_level: str = "vuln_effect"   # vuln_effect | e2e_impact
    achieved_evidence_level: str = "none"          # none | parser_diff | vuln_effect | e2e_impact

    verification_hints: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    field_confidence: dict[str, float] = field(default_factory=dict)
    adapter_kind: str = "package_service"  # source_build | package_service | compose_topo | stateful_auth | kernel_special

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
    def load(cls, path: str | Path) -> "KnowledgePack":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def knowledge_from_nvd_and_spec(
    cve_id: str,
    summary: dict[str, Any] | None = None,
    env_spec: Any = None,
    score: dict[str, Any] | None = None,
) -> KnowledgePack:
    """从 NVD summary + EnvSpec 组装知识包（缺项写 unknown，不臆造）。"""
    summary = summary or {}
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    k = KnowledgePack(cve_id=cve_id)
    k.sources.append({
        "type": "nvd", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "accessed_at": now,
    })

    desc = str(summary.get("description") or "")
    k.root_cause = desc[:800] if desc else "unknown"
    if not desc:
        k.unknowns.append("nvd_description")

    products = summary.get("products") or []
    if products:
        crit = str(products[0].get("criteria") or "")
        k.product = crit.split(":")[3] if crit.count(":") >= 4 else crit or "unknown"
        # CPE 版本边界粗提
        p0 = products[0]
        if p0.get("versionEndExcluding"):
            k.first_fixed_version = str(p0["versionEndExcluding"])
        elif p0.get("versionEndIncluding"):
            k.conflicts.append(
                f"only versionEndIncluding={p0['versionEndIncluding']}; "
                "first_fixed_version still unknown")
            k.unknowns.append("first_fixed_version")
        else:
            k.unknowns.append("first_fixed_version")
    else:
        k.product = "unknown"
        k.unknowns.append("product_cpe")

    refs = list(summary.get("references") or [])
    k.poc_refs = refs[:12]
    k.poc_available = bool(refs)
    for u in refs[:8]:
        k.sources.append({"type": "reference", "url": u, "accessed_at": now})

    if env_spec is not None:
        k.component = str(getattr(env_spec, "package", "") or k.component or "unknown")
        k.ecosystem = str(getattr(env_spec, "ecosystem", "") or "unknown")
        k.selected_vuln_version = str(
            getattr(env_spec, "vulnerable_version", "") or "unknown")
        # control_version：实验对照；可与 first_fixed 不同
        fv = str(getattr(env_spec, "fixed_version", "") or "")
        if fv:
            k.control_version = fv
            if not k.first_fixed_version:
                k.first_fixed_version = fv
                k.conflicts.append(
                    "control_version copied into first_fixed_version "
                    "because official boundary was missing — verify against vendor advisory")
        k.base_image = str(getattr(env_spec, "base_image", "") or "")
        k.runtime = str(getattr(env_spec, "language", "") or "")
        k.trigger_format = str(getattr(env_spec, "trigger_kind", "") or "unknown")
        if getattr(env_spec, "install", ""):
            k.dependencies.append(str(env_spec.install))
        eco = (k.ecosystem or "").lower()
        if eco in ("python", "java", "node", "ruby", "php"):
            k.adapter_kind = "package_service"
        elif eco in ("c", "cpp", "system"):
            k.adapter_kind = "source_build"
        else:
            k.adapter_kind = "package_service"

    if score and score.get("hard_block"):
        k.unknowns.append("reproduce_score_hard_block")
        k.kernel_limits = str(score.get("reason") or "")

    # 字段置信度粗标
    for name, val in (
        ("product", k.product), ("component", k.component),
        ("selected_vuln_version", k.selected_vuln_version),
        ("first_fixed_version", k.first_fixed_version),
        ("control_version", k.control_version),
    ):
        if not val or val == "unknown":
            k.field_confidence[name] = 0.0
        else:
            k.field_confidence[name] = 0.7 if name.startswith("first_") else 0.8

    k.required_evidence_level = "vuln_effect"
    k.achieved_evidence_level = "none"
    k.verification_hints.append(
        "Do not equate parser accept/reject differences with e2e request-smuggling impact.")
    return k
