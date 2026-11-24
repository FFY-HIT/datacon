"""Reproduce Score（论文 Appendix B.1 / Table 5）。

「The Reproduce Score is a quantitative metric used to assess the feasibility of
reproducing a CVE in a standard Docker environment ... a heuristic engine that
applies a set of scoring rules based on keyword matching and regular expressions
against the CVE metadata.」

用于 Stage 1 之前的候选筛选：低分 / 需要专有硬件或特定 OS 的 CVE 直接判为
irreproducible，避免把资源浪费在不可能容器化的条目上（§4.2.1 三阶段筛选第一关）。
"""
from __future__ import annotations

import re
from typing import Any

# Table 5 规则：(类别, 判据, 分值, 命中正则/关键词)
_EVIDENCE_RULES = (
    ("Evidence", "PoC / Exploit URL", 30,
     re.compile(r"\b(poc|exploit|exploit-db|packetstorm|github\.com/.+/(poc|exploit))", re.I)),
    ("Evidence", "CISA KEV / SSVC", 20,
     re.compile(r"\b(cisa|kev|ssvc|known exploited)", re.I)),
    ("Evidence", "Patch / Commit URL", 15,
     re.compile(r"\b(commit|patch|diff|pull/\d+|/compare/)", re.I)),
    ("Evidence", "Attack Details", 5,
     re.compile(r"\b(payload|endpoint|parameter|request|bypass|injection|smuggl)", re.I)),
)
_STACK_RULES = (
    ("Tech Stack", "Python / Node.js", 20,
     re.compile(r"\b(python|pip|pypi|django|flask|node\.?js|npm|express|twisted|gevent)", re.I)),
    ("Tech Stack", "PHP / WordPress", 15,
     re.compile(r"\b(php|wordpress|plugin|composer|laravel|drupal)", re.I)),
    ("Tech Stack", "Java / Go / Rust", 8,
     re.compile(r"\b(java|maven|spring|golang|\bgo\b|cargo|rust\b)", re.I)),
    ("Tech Stack", "C / C++", 3,
     re.compile(r"\b(c\+\+|openssl|libcurl|kernel module|native library)", re.I)),
)
_FIRMWARE = re.compile(
    r"\b(tenda|netgear|tp-link|d-link|dlink|iot|firmware|router|bios|uefi|"
    r"android device|ip camera|printer firmware)\b", re.I)
_SYSTEM_OS = re.compile(
    r"\b(windows|macos|ios\b|ipados|kernel\b|hypervisor|activex|"
    r"kernel driver|bluez|bluetooth stack)\b", re.I)
_PROPRIETARY = re.compile(r"\b(proprietary|closed source|no public repository)\b", re.I)


def _text(summary: dict[str, Any]) -> str:
    return " ".join([
        summary.get("description", ""),
        " ".join(summary.get("references", [])),
        " ".join(summary.get("cwes", [])),
        " ".join(str(p.get("criteria", "")) for p in summary.get("products", [])),
    ])


def compute_score(summary: dict[str, Any], cfg: Any | None = None) -> dict[str, Any]:
    """返回总分、逐条命中的加点、约束惩罚与是否可容器化。"""
    blob = _text(summary)
    refs = " ".join(summary.get("references", []))
    desc = summary.get("description", "")

    breakdown: list[dict[str, Any]] = []
    score = 0
    for category, criteria, points, pat in _EVIDENCE_RULES:
        scope = refs if "URL" in criteria else blob
        if pat.search(scope):
            score += points
            breakdown.append({"category": category, "criteria": criteria,
                               "points": points})

    # 技术栈只取最高一档，避免简单相加放大（Table 5 是分类而非累加）
    stack_hit: dict[str, Any] | None = None
    for category, criteria, points, pat in _STACK_RULES:
        if pat.search(blob):
            stack_hit = {"category": category, "criteria": criteria, "points": points}
            break
    if stack_hit:
        score += stack_hit["points"]
        breakdown.append(stack_hit)

    penalties: list[str] = []
    if _FIRMWARE.search(blob):
        score -= 50
        penalties.append("Firmware / IoT 设备：-50")
    if _SYSTEM_OS.search(blob):
        score -= 30
        penalties.append("System / OS 依赖：-30")
    if _PROPRIETARY.search(blob):
        score -= 20
        penalties.append("专有软件 / 无公开源码：-20")

    threshold = int(getattr(cfg, "reproduce_score_min", 25)) if cfg else 25
    hard_block = bool(_FIRMWARE.search(blob) or _SYSTEM_OS.search(blob))
    reproducible = (score >= threshold) and not hard_block
    return {
        "score": score,
        "threshold": threshold,
        "breakdown": breakdown,
        "penalties": penalties,
        "reproducible": reproducible,
        "hard_block": hard_block,
        "reason": ("命中硬件/专有 OS 约束，Linux 容器无法表达" if hard_block else
                   f"得分 {score} {'>=' if reproducible else '<'} 阈值 {threshold}"),
    }
