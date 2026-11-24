"""Stage 0：CVE 链接 -> NVD 结构化记录 -> 蒸馏 Markdown。

论文 §3.2：「Raw CVE JSON entries are first converted to Markdown, filtering
extraneous metadata such as timestamps and organizational tags. This Markdown
format serves as the unified knowledge transfer medium between specialized
agents across stages.」
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def cve_id_from_input(value: str) -> str:
    m = CVE_RE.search(str(value or ""))
    if not m:
        raise ValueError(f"无法从输入解析 CVE 编号: {value!r}")
    return m.group(0).upper()


def nvd_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def fetch_cve(cve_id: str, cfg: Any, force: bool = False) -> dict[str, Any]:
    """优先读本地缓存（可离线复现），否则请求 NVD API 2.0，原始数据完整落盘。"""
    out = Path(cfg.nvd_dir) / f"{cve_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists() and not force:
        try:
            return json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    last: Exception | None = None
    for attempt in range(3):
        try:
            r = requests.get(NVD_API, params={"cveId": cve_id}, timeout=40)
            r.raise_for_status()
            data = r.json()
            if data.get("totalResults") != 1:
                raise ValueError(f"NVD 未返回唯一记录: totalResults={data.get('totalResults')}")
            out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            return data
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < 2:
                time.sleep(6 * (attempt + 1))
    raise RuntimeError(f"NVD API 拉取 {cve_id} 失败: {last}")


def raw_summary(raw: dict[str, Any]) -> dict[str, Any]:
    """把 NVD 原始 JSON 压成 Analyzer 需要的字段（丢弃时间戳与组织标签）。"""
    cve = (raw.get("vulnerabilities") or [{}])[0].get("cve", {})
    desc = next((x["value"] for x in cve.get("descriptions", [])
                 if x.get("lang") == "en"), "")
    refs = list(dict.fromkeys(
        r.get("url", "") for r in cve.get("references", []) if r.get("url")))
    cwes = [d.get("value") for w in cve.get("weaknesses", [])
            for d in w.get("description", []) if d.get("lang") == "en"]
    cvss: dict[str, Any] = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if cve.get("metrics", {}).get(key):
            cvss = cve["metrics"][key][0].get("cvssData", {}) or {}
            break
    products: list[dict[str, Any]] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    products.append({
                        "criteria": m.get("criteria", ""),
                        "versionStartIncluding": m.get("versionStartIncluding", ""),
                        "versionStartExcluding": m.get("versionStartExcluding", ""),
                        "versionEndIncluding": m.get("versionEndIncluding", ""),
                        "versionEndExcluding": m.get("versionEndExcluding", ""),
                    })
    return {
        "cve_id": cve.get("id", ""),
        "description": desc,
        "references": refs,
        "cwes": cwes,
        "cvss": cvss,
        "products": products,
        "source_identifier": cve.get("sourceIdentifier", ""),
    }


def _range_text(p: dict[str, Any]) -> str:
    parts = []
    if p.get("versionStartIncluding"):
        parts.append(">= " + p["versionStartIncluding"])
    if p.get("versionStartExcluding"):
        parts.append("> " + p["versionStartExcluding"])
    if p.get("versionEndIncluding"):
        parts.append("<= " + p["versionEndIncluding"])
    if p.get("versionEndExcluding"):
        parts.append("< " + p["versionEndExcluding"])
    return ", ".join(parts) or "未标注"


def to_cve_markdown(cve_id: str, summary: dict[str, Any],
                     score: dict[str, Any]) -> str:
    """按论文 Appendix A.2 的 CVE-2025-10686.md 版式蒸馏 Markdown。"""
    lines = [
        f"# {cve_id}",
        "",
        "## Basic Information",
        f"- **Reproduce Score**: {score.get('score', 0)}",
        f"- **CVSS Score**: {summary['cvss'].get('baseScore', 'N/A')}",
        f"- **CWE**: {', '.join(summary['cwes']) or 'N/A'}",
        f"- **Container Reproducible**: {score.get('reproducible', False)}",
        "",
        "## Description",
        summary["description"] or "(NVD 未提供英文描述)",
        "",
        "## Affected Products",
    ]
    if summary["products"]:
        for p in summary["products"]:
            lines += [f"### {p['criteria']}", f"**Versions:** {_range_text(p)}", ""]
    else:
        lines += ["(NVD configurations 未提供 CPE 匹配)", ""]
    lines += ["## References and POCs", "### POC/Exploits"]
    for u in summary["references"]:
        lines.append(f"- {u}")
    lines += [
        "",
        "## Reproducibility Assessment",
        f"- Score: {score.get('score', 0)} (threshold "
        f"{score.get('threshold', 0)})",
    ]
    for b in score.get("breakdown", []):
        lines.append(f"- {b['category']}: {b['criteria']} -> {b['points']:+d}")
    if score.get("penalties"):
        for r in score["penalties"]:
            lines.append(f"- Constraint: {r}")
    return "\n".join(lines) + "\n"


def resolve(cve_input: str, cfg: Any, force: bool = False,
            score: dict[str, Any] | None = None) -> dict[str, Any]:
    """Stage 0 入口：返回 cve_id / nvd_url / markdown / summary / raw。"""
    cve_id = cve_id_from_input(cve_input)
    raw = fetch_cve(cve_id, cfg, force=force)
    summary = raw_summary(raw)
    return {
        "cve_id": cve_id,
        "nvd_url": nvd_url(cve_id),
        "summary": summary,
        "raw": raw,
        "markdown": to_cve_markdown(cve_id, summary, score or {}),
    }
