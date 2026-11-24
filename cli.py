"""CVE-Factory CLI — 纯 Skill + Cursor（Agent-only）。

Cursor Agent 按 /cve-repro 写 tasks/<CVE>/，本命令只构建镜像并跑四道门。
不调用任何工厂侧 LLM（无 DMX / auto / batch）。

  .\\.venv\\Scripts\\python cli.py verify --cve CVE-2023-46137 --mode robust --cursor-model <模型名> --attempt 1
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cfactory.config import Config, load_dotenv  # noqa: E402

load_dotenv()


def make_cfg(args: argparse.Namespace) -> Config:
    cfg = Config()
    if getattr(args, "tag", None):
        cfg.result_tag = args.tag
    return cfg


def _print_result(r) -> None:
    print("\n=== 结果 ===")
    print(f"CVE       : {r.cve_id}")
    print(f"Mode      : {r.mode}")
    print(f"Status    : {r.status}")
    print(f"Adapter   : {r.adapter_kind}")
    print(f"Model     : {getattr(r, 'model', '') or '-'}")
    print(f"Iters     : {getattr(r, 'iterations', 0)}")
    fr = r.factory_result or {}
    if fr.get("vulnerable_image"):
        print(f"Image     : {fr.get('vulnerable_image')} / "
              f"{fr.get('fixed_image') or '-'}")
        print(f"Task      : {fr.get('task_dir')}")
    print(f"Matrix    : {json.dumps((r.matrix or {}).get('passed_gates', {}), ensure_ascii=False)}")
    print(f"Conclusion: {r.conclusion}")
    print(f"Elapsed   : {r.elapsed:.1f}s")
    if r.evidence_paths:
        print(f"Artifacts : {r.evidence_paths[-1]}")


def cmd_verify(args: argparse.Namespace) -> None:
    cfg = make_cfg(args)
    from cfactory.autoloop.agent_verify import run_agent_verify
    mode = (args.mode or "robust").lower()
    model = args.cursor_model or "cursor-agent"
    relaxed = not bool(args.strict)
    print(f"[verify] cve={args.cve} mode={mode} cursor_model={model} "
          f"attempt={args.attempt} relaxed={relaxed}", flush=True)
    r = run_agent_verify(
        args.cve, cfg=cfg, mode=mode, cursor_model=model,
        attempt=int(args.attempt), relaxed=relaxed)
    _print_result(r)


def main() -> None:
    p = argparse.ArgumentParser(
        description="CVE 复现验证（纯 Skill+Cursor；仅 verify）")
    sub = p.add_subparsers(dest="cmd", required=True)

    verify = sub.add_parser(
        "verify",
        help="构建 tasks/<CVE> 并跑四道门（不调工厂 LLM）")
    verify.add_argument("--cve", required=True, help="CVE-YYYY-NNNN")
    verify.add_argument(
        "--cursor-model", default="cursor-agent",
        help="记录用的 Cursor 模型名（换模型即换实验 LLM）")
    verify.add_argument("--attempt", type=int, default=1, help="本对话第几次迭代")
    verify.add_argument("--mode", choices=["robust", "fast"], default="robust")
    verify.add_argument(
        "--strict", action="store_true",
        help="严格四道门（默认放宽）")
    verify.add_argument("--tag", help="结果文件后缀")
    verify.set_defaults(func=cmd_verify)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
