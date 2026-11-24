"""验收约定：先定义怎样才算复现，再搭环境。"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .knowledge import KnowledgePack


@dataclass
class AcceptanceContract:
    cve_id: str = ""
    mode: str = "robust"  # robust | fast

    normal_input_desc: str = ""
    normal_expected: str = ""
    vuln_input_desc: str = ""
    vuln_expected: str = ""
    cve_linked_evidence: list[str] = field(default_factory=list)

    fixed_expected: str = ""
    require_fixed_control: bool = True
    require_repeat: bool = True
    require_clean_rebuild: bool = True
    repeat_count: int = 2

    # 竞态/时序类不可套用「两次一致」
    statistical_verdict: bool = False
    statistical_trials: int = 0

    required_evidence_level: str = "vuln_effect"
    success_marker: str = "VULNERABILITY_TRIGGERED"
    evidence_patterns: list[str] = field(default_factory=list)

    # 放行门：漏洞版 / 对照版 × 正常 / 漏洞输入
    matrix_required: dict[str, bool] = field(default_factory=lambda: {
        "vuln_normal_pass": True,
        "vuln_trigger_pass": True,
        "fixed_normal_pass": True,
        "fixed_trigger_fail": True,  # 修复版不应触发
    })

    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                     encoding="utf-8")
        return p


def build_acceptance(knowledge: KnowledgePack, mode: str,
                     *, relaxed: bool = False) -> AcceptanceContract:
    mode = (mode or "robust").lower()
    ac = AcceptanceContract(
        cve_id=knowledge.cve_id,
        mode=mode,
        normal_input_desc="benign request / API call that exercises healthy paths",
        normal_expected="service responds successfully; FACTORY_FUNC_PASS=1",
        vuln_input_desc=knowledge.trigger_format or "crafted input matching CVE trigger",
        vuln_expected="CVE-linked observable effect; success_marker printed",
        cve_linked_evidence=list(knowledge.verification_hints)
        or ["marker + evidence_tokens corresponding to root cause"],
        fixed_expected="same normal function; vuln effect absent",
        required_evidence_level=knowledge.required_evidence_level,
    )
    if mode == "fast":
        ac.require_fixed_control = False
        ac.require_repeat = False
        ac.require_clean_rebuild = False
        ac.repeat_count = 1
        ac.matrix_required = {
            "vuln_normal_pass": True,
            "vuln_trigger_pass": True,   # 宣称 FAST_VERIFIED 时必须
            "fixed_normal_pass": False,
            "fixed_trigger_fail": False,
        }
        ac.notes.append("Fast mode: fixed control / repeat / rebuild deferred.")
    elif relaxed:
        # Agent-only 默认：核心门放宽，fixed/repeat 尽力而为
        ac.require_fixed_control = True
        ac.require_repeat = False
        ac.require_clean_rebuild = False
        ac.repeat_count = 1
        ac.matrix_required = {
            "vuln_normal_pass": True,
            "vuln_trigger_pass": True,
            "fixed_normal_pass": False,   # 软门：不挡 VERIFIED
            "fixed_trigger_fail": True,   # 有 fixed 镜像时仍看「不触发」
        }
        ac.notes.append(
            "Relaxed agent mode: VERIFIED if vuln normal+trigger; "
            "fixed non-trigger required only when fixed image exists; "
            "repeat/rebuild/fixed_normal not required.")
    else:
        ac.require_fixed_control = True
        ac.require_repeat = True
        ac.require_clean_rebuild = True
        ac.repeat_count = 2
        ac.notes.append(
            "Robust mode: full matrix + repeat after reset + one clean rebuild.")
        ac.notes.append(
            "Agent self-report is not acceptance; scripts decide.")
    return ac
