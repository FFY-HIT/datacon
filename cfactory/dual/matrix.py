"""测试矩阵：漏洞版/对照版 × 正常输入/漏洞输入 + 可选重复与干净重建。"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..poc.docker_exec import DockerPoCExecutor
from ..poc.models import PoC
from .acceptance import AcceptanceContract


@dataclass
class MatrixResult:
    vuln_normal_pass: bool | None = None
    vuln_trigger_pass: bool | None = None
    fixed_normal_pass: bool | None = None
    fixed_trigger_fail: bool | None = None  # True = 修复版未触发（符合预期）
    repeat_ok: bool | None = None
    rebuild_ok: bool | None = None
    runs: list[dict[str, Any]] = field(default_factory=list)
    evidence_dir: str = ""
    passed_gates: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_text(task_dir: Path, name: str) -> str:
    p = task_dir / name
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""


def _normal_probe_poc(port: int) -> PoC:
    code = f'''"""Normal baseline probe."""
import socket, sys
PORT = {port or 18080}
try:
    s = socket.create_connection(("127.0.0.1", PORT), timeout=3)
    s.sendall(b"GET / HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n")
    data = s.recv(4096)
    s.close()
    ok = bool(data)
    print("FACTORY_FUNC_PROBE=" + ("1" if ok else "0"))
    sys.exit(0 if ok else 1)
except Exception as e:
    print("FACTORY_FUNC_PROBE=0")
    print(str(e))
    sys.exit(1)
'''
    return PoC(code=code, language="python", filename="normal_probe.py",
               markers=["FACTORY_FUNC_PROBE=1"])


def run_test_matrix(
    *,
    acceptance: AcceptanceContract,
    task_dir: str | Path,
    vulnerable_image: str,
    fixed_image: str = "",
    port: int = 18080,
    marker: str = "VULNERABILITY_TRIGGERED",
    docker: str = "docker",
    network: str = "none",
    evidence_dir: str | Path = "",
    trigger_poc_code: str = "",
    extra_run_args: list[str] | None = None,
) -> MatrixResult:
    """执行矩阵。验收脚本判定，不采信 Agent 自报。"""
    task_dir = Path(task_dir)
    evid = Path(evidence_dir) if evidence_dir else task_dir / "evidence_matrix"
    evid.mkdir(parents=True, exist_ok=True)
    out = MatrixResult(evidence_dir=str(evid))

    trigger_code = trigger_poc_code or _load_text(task_dir, "poc_reference.py")
    if not trigger_code.strip():
        out.notes.append("no trigger PoC code; vuln_trigger_pass left None")
        trigger = None
    else:
        trigger = PoC(code=trigger_code, language="python",
                      filename="matrix_trigger.py", markers=[marker])

    normal = _normal_probe_poc(port)
    ex = DockerPoCExecutor(
        vulnerable_image=vulnerable_image, fixed_image=fixed_image,
        port=port, network=network, poc_dir=evid / "runs", docker=docker,
        extra_args=extra_run_args)

    def _one(label: str, image: str, poc: PoC, expect_marker: bool) -> dict[str, Any]:
        if image == vulnerable_image:
            r = ex.run_vulnerable(poc)
        else:
            r = ex.run_fixed(poc) or ex.run_vulnerable(poc)
        hit = marker in (r.stdout or "") if expect_marker else (
            "FACTORY_FUNC_PROBE=1" in (r.stdout or "") or r.exit_code == 0)
        rec = {
            "label": label, "image": image, "exit_code": r.exit_code,
            "timed_out": r.timed_out, "marker_or_func_hit": hit,
            "stdout_tail": (r.stdout or "")[-500:],
            "stderr_tail": (r.stderr or "")[-300:],
            "ts": time.strftime("%H:%M:%S"),
        }
        (evid / f"{label}.json").write_text(
            json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
        out.runs.append(rec)
        return rec

    # 漏洞版：正常
    if acceptance.matrix_required.get("vuln_normal_pass"):
        rec = _one("vuln_normal", vulnerable_image, normal, expect_marker=False)
        out.vuln_normal_pass = bool(rec["marker_or_func_hit"]) and rec["exit_code"] == 0

    # 漏洞版：触发
    if acceptance.matrix_required.get("vuln_trigger_pass") and trigger:
        _one("vuln_trigger", vulnerable_image, trigger, expect_marker=True)
        last = ex.log[-1] if ex.log else {}
        out.vuln_trigger_pass = marker in str(last.get("stdout") or "")

    # 修复对照
    if fixed_image and acceptance.require_fixed_control:
        if acceptance.matrix_required.get("fixed_normal_pass"):
            rec = _one("fixed_normal", fixed_image, normal, expect_marker=False)
            out.fixed_normal_pass = bool(rec["marker_or_func_hit"])
        if acceptance.matrix_required.get("fixed_trigger_fail") and trigger:
            rec = _one("fixed_trigger", fixed_image, trigger, expect_marker=True)
            last = ex.log[-1] if ex.log else {}
            triggered_on_fixed = marker in str(last.get("stdout") or "")
            out.fixed_trigger_fail = not triggered_on_fixed  # True=好

    # 重复（重置后）
    if acceptance.require_repeat and trigger and out.vuln_trigger_pass:
        oks = []
        for i in range(max(1, acceptance.repeat_count)):
            rec = _one(f"vuln_trigger_repeat_{i}", vulnerable_image, trigger,
                       expect_marker=True)
            last = ex.log[-1] if ex.log else {}
            oks.append(marker in str(last.get("stdout") or ""))
        out.repeat_ok = all(oks) if not acceptance.statistical_verdict else (
            sum(oks) >= max(1, len(oks) // 2))
    elif not acceptance.require_repeat:
        out.notes.append("repeat deferred (fast mode)")

    # 干净重建标记：由上层在 docker build 后再调一次 matrix 填写
    if not acceptance.require_clean_rebuild:
        out.notes.append("clean rebuild deferred (fast mode)")

    req = acceptance.matrix_required
    gates = {}
    if req.get("vuln_normal_pass"):
        gates["vuln_normal_pass"] = bool(out.vuln_normal_pass)
    if req.get("vuln_trigger_pass"):
        gates["vuln_trigger_pass"] = bool(out.vuln_trigger_pass)
    if req.get("fixed_normal_pass") and acceptance.require_fixed_control:
        gates["fixed_normal_pass"] = bool(out.fixed_normal_pass)
    if req.get("fixed_trigger_fail") and acceptance.require_fixed_control:
        gates["fixed_trigger_fail"] = bool(out.fixed_trigger_fail)
    if acceptance.require_repeat:
        gates["repeat_ok"] = bool(out.repeat_ok)
    out.passed_gates = gates
    return out
