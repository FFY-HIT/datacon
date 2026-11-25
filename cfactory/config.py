"""CVE-Factory 配置（纯 Skill + Cursor / Agent-only）。

决策 LLM 在 Cursor；本包只做 Docker 构建与矩阵验收。
可选 .env：镜像加速等，不需要 DMX_API_KEY。
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_AUTO_ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path: str | Path | None = None, *,
                override: bool = False) -> Path | None:
    """加载项目根目录 `.env` 到 os.environ（不覆盖已有环境变量）。"""
    env_path = Path(path) if path else (_AUTO_ROOT / ".env")
    if not env_path.is_file():
        return None
    try:
        text = env_path.read_text(encoding="utf-8")
    except OSError:
        return None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        key, _, val = line.partition("=")
        key = key.strip()
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if override or key not in os.environ:
            os.environ[key] = val
    return env_path


load_dotenv()


@dataclass
class Config:
    # ---- Docker ----
    docker: str = "docker"
    network_mode: str = "none"
    target_platform: str = "linux/amd64"
    max_build_seconds: int = int(os.getenv("CVE_FACTORY_MAX_BUILD_SECONDS", "600"))
    max_run_seconds: int = 180
    pip_index_url: str = field(default_factory=lambda: os.getenv(
        "CVE_FACTORY_PIP_INDEX", "https://mirrors.tencent.com/pypi/simple/"))
    docker_hub_mirror: str = field(default_factory=lambda: os.getenv(
        "CVE_FACTORY_DOCKER_HUB_MIRROR", "dockerproxy.net").strip())
    # 额外 docker run 参数（空格分隔），供需要内核能力的任务使用，
    # 如 iptables 类 "--cap-add NET_ADMIN --cap-add NET_RAW"。默认空=行为不变。
    docker_run_extra: str = field(default_factory=lambda: os.getenv(
        "CVE_FACTORY_DOCKER_RUN_EXTRA", "").strip())

    def run_extra_args(self) -> list[str]:
        import shlex
        try:
            return shlex.split(self.docker_run_extra)
        except ValueError:
            return self.docker_run_extra.split()

    # ---- 路径 ----
    root: str = str(_AUTO_ROOT)
    data_dir: str = ""
    nvd_dir: str = ""
    tasks_dir: str = ""
    output_dir: str = ""
    logs_dir: str = ""
    result_tag: str = ""

    # ---- 筛选（verify 内可选参考） ----
    enable_reproduce_filter: bool = False
    reproduce_score_min: int = 25

    verbose: bool = True

    def __post_init__(self) -> None:
        root = Path(self.root)
        if self.root == str(_AUTO_ROOT) or not (root / "cfactory" / "__init__.py").exists():
            root = _AUTO_ROOT
        load_dotenv(root / ".env")
        self.root = str(root)
        self.data_dir = str(root / "data")
        self.nvd_dir = str(root / "data" / "nvd")
        self.tasks_dir = str(root / "tasks")
        self.output_dir = str(root / "output")
        self.logs_dir = str(root / "output" / "logs")
        for p in (self.data_dir, self.nvd_dir, self.tasks_dir,
                  self.output_dir, self.logs_dir):
            Path(p).mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
