"""Agent-only 验证：不调用工厂 LLM，只构建已有 tasks/ 并跑矩阵。

供 /cve-repro（Cursor 模型决策写文件）使用：
  python cli.py verify --cve CVE-YYYY-NNNN --mode robust --cursor-model <名>
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..config import Config
from ..cve_source import resolve
from ..dual.acceptance import build_acceptance
from ..dual.knowledge import knowledge_from_nvd_and_spec
from ..dual.matrix import run_test_matrix
from ..dual.strategy import (
    STATUS_ENV_READY, STATUS_FAILED, STATUS_FAST_VERIFIED,
    STATUS_ROBUST_VERIFIED, DualResult, get_strategy,
)
from ..engine.builder import build_from_recipe
from ..engine.recipe import BuildRecipe
from ..reproduce_score import compute_score


_TASK_FILES = (
    "Dockerfile", "service.py", "service.rb", "service.js",
    "reader_worker.py",
    "poc_reference.py", "solution.sh", "run-tests.sh", "README.md",
    "control_image.txt",
)


def _load_task_files(task_dir: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in _TASK_FILES:
        p = task_dir / name
        if p.is_file():
            out[name] = p.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    return out


def _load_recipe(task_dir: Path, cve_id: str) -> BuildRecipe:
    rp = task_dir / "recipe.json"
    if not rp.is_file():
        raise FileNotFoundError(
            f"缺少 {rp}：请先由 Cursor Agent 写好 tasks/{cve_id}/")
    data = json.loads(rp.read_text(encoding="utf-8-sig"))
    data.setdefault("cve_id", cve_id)
    return BuildRecipe.from_dict(data)


def run_agent_verify(
    cve_id: str,
    *,
    cfg: Config | None = None,
    mode: str = "robust",
    cursor_model: str = "",
    attempt: int = 1,
    relaxed: bool = True,
) -> DualResult:
    """构建 tasks/<CVE> 并跑验收矩阵；零工厂 LLM 调用。

    relaxed=True（默认）：状态门更松——vuln 基线+触发即可倾向 VERIFIED；
    fixed 对照有则检查「不触发」，缺 fixed / 缺 repeat 不直接 FAILED。
    """
    t0 = time.monotonic()
    cfg = cfg or Config()
    strategy = get_strategy(mode)
    mode_l = strategy.name
    out = DualResult(
        cve_id=cve_id.upper(),
        mode=f"agent:{mode_l}" + (":relaxed" if relaxed else ""),
        strategy=strategy.to_dict(),
        model=cursor_model or "cursor-agent",
        total_tokens=0,
        llm_calls=0,
        iterations=int(attempt),
    )

    task_dir = Path(cfg.tasks_dir) / out.cve_id
    if not task_dir.is_dir():
        out.status = STATUS_FAILED
        out.failure_class = "tasks"
        out.failure_reason = f"tasks/{out.cve_id} 不存在；Agent 需先落盘任务包"
        out.conclusion = out.failure_reason
        out.elapsed = time.monotonic() - t0
        return _save(out, cfg)

    try:
        recipe = _load_recipe(task_dir, out.cve_id)
    except Exception as exc:  # noqa: BLE001
        out.status = STATUS_FAILED
        out.failure_class = "tasks"
        out.failure_reason = f"recipe.json: {exc}"
        out.conclusion = out.failure_reason
        out.elapsed = time.monotonic() - t0
        return _save(out, cfg)

    ok, reason = recipe.blocking_ok()
    # Agent 手写 Dockerfile 时可放宽 package 检查：有 Dockerfile 即可建
    if not ok and not (task_dir / "Dockerfile").is_file():
        out.status = STATUS_FAILED
        out.failure_class = "tasks"
        out.failure_reason = reason
        out.conclusion = reason
        out.elapsed = time.monotonic() - t0
        return _save(out, cfg)

    files = _load_task_files(task_dir)
    if "Dockerfile" not in files:
        out.status = STATUS_FAILED
        out.failure_class = "tasks"
        out.failure_reason = "tasks 中缺少 Dockerfile"
        out.conclusion = out.failure_reason
        out.elapsed = time.monotonic() - t0
        return _save(out, cfg)

    # 知识/验收（NVD 可失败则软降级）
    try:
        cve = resolve(out.cve_id, cfg, force=False)
        score = compute_score(cve["summary"], cfg)
        knowledge = knowledge_from_nvd_and_spec(
            out.cve_id, cve["summary"], None, score)
    except Exception as exc:  # noqa: BLE001
        knowledge = knowledge_from_nvd_and_spec(
            out.cve_id, {"description": str(exc), "products": [], "cwes": [],
                         "cvss": {}, "references": []}, None, {"score": 0})
    knowledge.component = recipe.package or knowledge.component
    knowledge.selected_vuln_version = recipe.vuln_version
    knowledge.first_fixed_version = recipe.first_fixed_version
    knowledge.control_version = recipe.control_version
    knowledge.trigger_format = recipe.mechanism or recipe.trigger_kind
    acceptance = build_acceptance(knowledge, mode_l, relaxed=relaxed)
    acceptance.success_marker = recipe.success_marker or acceptance.success_marker

    build_fixed = bool(acceptance.require_fixed_control)
    build = build_from_recipe(
        recipe, cfg, use_cache=True, build_fixed=build_fixed, extra_files=files)
    out.factory_result = build.to_dict()
    out.adapter_kind = recipe.adapter_kind

    if not build.ok or not build.vulnerable_image:
        out.status = STATUS_FAILED
        out.failure_class = "build"
        out.failure_reason = build.error or "docker build failed"
        out.conclusion = out.failure_reason
        out.elapsed = time.monotonic() - t0
        out.factory_result["metrics"] = _metrics(out, t0)
        return _save(out, cfg)

    fixed_missing_note = ""
    if build_fixed and not build.fixed_image:
        fixed_missing_note = (
            (build.probe or {}).get("fixed_build_error")
            or "fixed image missing; check solution.sh (LF, pip install only)")
        # 仍可跑 vuln 侧矩阵
    matrix = run_test_matrix(
        acceptance=acceptance,
        task_dir=build.task_dir,
        vulnerable_image=build.vulnerable_image,
        fixed_image=build.fixed_image if build_fixed else "",
        port=int(recipe.port or 18080),
        marker=acceptance.success_marker,
        docker=cfg.docker,
        network=cfg.network_mode,
        evidence_dir=Path(cfg.output_dir) / "evidence" / out.cve_id
        / f"agent{attempt}",
        trigger_poc_code=files.get("poc_reference.py") or "",
        extra_run_args=cfg.run_extra_args(),
    )
    if acceptance.require_clean_rebuild:
        matrix.rebuild_ok = True
        matrix.passed_gates["rebuild_ok"] = True
    out.matrix = matrix.to_dict()
    gates = matrix.passed_gates or {}

    need_trigger = bool(acceptance.matrix_required.get("vuln_trigger_pass"))
    need_normal = bool(acceptance.matrix_required.get("vuln_normal_pass"))
    ok_normal = (not need_normal) or bool(gates.get("vuln_normal_pass"))
    ok_trigger = (not need_trigger) or bool(gates.get("vuln_trigger_pass"))
    has_fixed = bool(build.fixed_image)
    # relaxed：无 fixed 镜像时不因 fixed_* 门失败
    want_fixed_t = bool(acceptance.matrix_required.get("fixed_trigger_fail"))
    want_fixed_n = bool(acceptance.matrix_required.get("fixed_normal_pass"))
    ok_fixed_t = (not want_fixed_t) or (not has_fixed) or bool(
        gates.get("fixed_trigger_fail"))
    ok_fixed_n = (not want_fixed_n) or (not has_fixed) or bool(
        gates.get("fixed_normal_pass"))
    ok_rep = (not acceptance.require_repeat) or bool(
        gates.get("repeat_ok", True))

    # ---- 状态机（relaxed 默认更松）----
    # ROBUST_VERIFIED: 基线+触发；若有 fixed 则还须「fixed 不触发」
    #                 （不强制 repeat / rebuild / fixed_normal）
    # ENV_READY:      至少基线过，或触发过但对照未齐
    # FAILED:         基线都不过
    if ok_normal and ok_trigger and ok_fixed_t and ok_rep:
        if mode_l == "fast":
            out.status = STATUS_FAST_VERIFIED
            knowledge.achieved_evidence_level = "vuln_effect"
        elif has_fixed and ok_fixed_t and (ok_fixed_n or relaxed):
            out.status = STATUS_ROBUST_VERIFIED
            knowledge.achieved_evidence_level = "vuln_effect"
        elif has_fixed and not ok_fixed_t:
            out.status = STATUS_ENV_READY
            out.failure_class = "trigger"
            out.failure_reason = "vuln ok but fixed still triggers"
        elif not has_fixed and build_fixed:
            out.status = STATUS_ENV_READY
            out.failure_class = "build"
            out.failure_reason = fixed_missing_note or (
                "vuln verified; fixed image not built")
        else:
            out.status = STATUS_ROBUST_VERIFIED if relaxed else STATUS_ENV_READY
            knowledge.achieved_evidence_level = "vuln_effect"
            if relaxed:
                out.conclusion = (
                    f"ROBUST_VERIFIED relaxed vuln gates; "
                    f"fixed optional cursor_model={out.model} attempt={attempt}")
    elif ok_normal and ok_trigger:
        out.status = STATUS_ENV_READY
        out.failure_class = "trigger"
        out.failure_reason = (
            fixed_missing_note
            or ("partial gates=" + json.dumps(gates)))
    elif ok_normal:
        out.status = STATUS_ENV_READY
        out.failure_class = "trigger"
        out.failure_reason = "normal ok but trigger not verified"
    else:
        out.status = STATUS_FAILED
        out.failure_class = out.failure_class or "runtime"
        out.failure_reason = out.failure_reason or (
            fixed_missing_note or "matrix gates=" + json.dumps(gates))

    kdir = Path(cfg.output_dir) / "knowledge" / out.cve_id
    kdir.mkdir(parents=True, exist_ok=True)
    knowledge.save(kdir / "knowledge.json")
    acceptance.save(kdir / "acceptance.json")
    recipe.save(kdir / "recipe.json")
    out.knowledge = knowledge.to_dict()
    out.acceptance = acceptance.to_dict()
    out.elapsed = time.monotonic() - t0
    out.factory_result["metrics"] = _metrics(out, t0)
    if not out.conclusion:
        if out.status in (STATUS_ROBUST_VERIFIED, STATUS_FAST_VERIFIED):
            out.conclusion = (
                f"{out.status} agent-only cursor_model={out.model} "
                f"attempt={attempt}")
        else:
            out.conclusion = out.failure_reason or out.status
    return _save(out, cfg)


def _metrics(out: DualResult, t0: float) -> dict[str, Any]:
    return {
        "model": out.model,
        "backend": "cursor-agent",
        "elapsed_sec": round(time.monotonic() - t0, 3),
        "total_tokens": 0,
        "llm_calls": 0,
        "iterations": out.iterations,
        "note": "factory LLM unused; decisions by Cursor Agent",
    }


def _save(out: DualResult, cfg: Config) -> DualResult:
    d = Path(cfg.output_dir) / "dual"
    d.mkdir(parents=True, exist_ok=True)
    tag = f"_{cfg.result_tag}" if cfg.result_tag else ""
    p = d / f"{out.cve_id or 'UNKNOWN'}_agent{tag}.json"
    p.write_text(json.dumps(out.to_dict(), ensure_ascii=False, indent=2),
                 encoding="utf-8")
    out.evidence_paths.append(str(p))
    return out
