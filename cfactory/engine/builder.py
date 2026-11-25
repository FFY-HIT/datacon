"""确定性构建：模板落盘 → docker build（默认可层缓存）。"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..docker_runtime import (
    DockerRuntime, ensure_dockerfile_copy_task, rewrite_dockerfile_from, _run,
)
from .recipe import BuildRecipe
from .templates import materialize


@dataclass
class BuildOutcome:
    ok: bool = False
    task_dir: str = ""
    vulnerable_image: str = ""
    fixed_image: str = ""
    build_log_tail: str = ""
    error: str = ""
    duration: float = 0.0
    files: list[str] = field(default_factory=list)
    probe: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "task_dir": self.task_dir,
            "vulnerable_image": self.vulnerable_image,
            "fixed_image": self.fixed_image,
            "build_log_tail": self.build_log_tail[-2000:],
            "error": self.error, "duration": self.duration,
            "files": self.files, "probe": self.probe,
        }


def write_task(recipe: BuildRecipe, task_dir: Path,
               extra: dict[str, str] | None = None) -> list[str]:
    task_dir.mkdir(parents=True, exist_ok=True)
    files = materialize(recipe)
    if extra:
        files.update(extra)
    written = []
    for name, content in files.items():
        p = task_dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        # Dockerfile 内 pip index：用 Config 环境，写文件时再替换
        p.write_text(content, encoding="utf-8")
        written.append(name)
        if name.endswith(".sh"):
            try:
                p.chmod(p.stat().st_mode | 0o111)
            except OSError:
                pass
    return written


_ALT_MIRRORS = (
    "docker.m.daocloud.io",
    "docker.1ms.run",
    "hub.rat.dev",
)


def _ensure_hub_image_local(cfg: Config, image: str) -> str:
    """确保官方短名镜像在本地；必要时从备用镜像源拉取并打短名标签。"""
    from ..docker_runtime import _canonical_hub_short, _image_exists_locally, _run
    short = _canonical_hub_short(image, cfg.docker_hub_mirror or "")
    if _image_exists_locally(cfg.docker, short):
        return short
    candidates = [short, f"docker.io/library/{short}"]
    for m in _ALT_MIRRORS:
        candidates.append(f"{m}/library/{short}")
    if cfg.docker_hub_mirror:
        candidates.append(f"{cfg.docker_hub_mirror.rstrip('/')}/library/{short}")
    for ref in candidates:
        if _image_exists_locally(cfg.docker, ref):
            if ref != short:
                _run([cfg.docker, "tag", ref, short], 60)
            return short
        rc, out, err, _ = _run([cfg.docker, "pull", ref], cfg.max_build_seconds)
        if rc == 0:
            if ref != short:
                _run([cfg.docker, "tag", ref, short], 60)
            return short
    return short


def _docker_build(cfg: Config, task_dir: Path, tag: str, *,
                  use_cache: bool, label: str, cve_id: str) -> dict[str, Any]:
    df = task_dir / "Dockerfile"
    if df.is_file():
        original = df.read_text(encoding="utf-8", errors="replace")
        # 注入 pip 镜像
        text = original.replace(
            "${PIP_INDEX_URL:-https://pypi.org/simple}",
            cfg.pip_index_url or "https://pypi.org/simple",
        )
        text = ensure_dockerfile_copy_task(text)
        # 预拉 FROM 基础镜像（避开坏掉的默认代理）
        for m in re.finditer(
                r"^FROM\s+(?:--\S+\s+)*(\S+)", text, flags=re.I | re.M):
            img = m.group(1)
            if "/" not in img.split(":", 1)[0] or img.startswith("docker"):
                try:
                    _ensure_hub_image_local(cfg, img)
                except Exception:  # noqa: BLE001
                    pass
        # 本地已有基础镜像则不走 dockerproxy；否则再改写到镜像代理
        text = rewrite_dockerfile_from(
            text, cfg.docker_hub_mirror or "",
            docker=cfg.docker, prefer_local=True)
        if text != original:
            df.write_text(text, encoding="utf-8")

    env = dict(os.environ)
    env["DOCKER_BUILDKIT"] = "1"
    cmd = [cfg.docker, "build", "--progress=plain",
           "--platform", cfg.target_platform, "-t", tag, "."]
    if not use_cache:
        cmd.insert(2, "--no-cache")
    rc, out, err, dur = _run(cmd, cfg.max_build_seconds,
                             cwd=str(task_dir), env=env)
    log = (out or "") + "\n" + (err or "")
    logs = Path(cfg.logs_dir)
    logs.mkdir(parents=True, exist_ok=True)
    (logs / f"{cve_id}_{label}.log").write_text(log, encoding="utf-8")
    return {
        "success": rc == 0, "tag": tag, "exit_code": rc,
        "duration": dur, "log_tail": log[-2500:],
        "first_error": "" if rc == 0 else log[-800:],
    }


def build_from_recipe(
    recipe: BuildRecipe,
    cfg: Config,
    *,
    use_cache: bool = True,
    build_fixed: bool = False,
    extra_files: dict[str, str] | None = None,
) -> BuildOutcome:
    t0 = time.monotonic()
    out = BuildOutcome()
    ok, reason = recipe.blocking_ok()
    if not ok:
        out.error = reason
        out.duration = time.monotonic() - t0
        return out

    task_dir = Path(cfg.tasks_dir) / recipe.cve_id
    # 清理旧 Agent 产物干扰：覆盖写入模板文件即可
    written = write_task(recipe, task_dir, extra=extra_files)
    out.task_dir = str(task_dir)
    out.files = written

    if not (task_dir / "Dockerfile").is_file():
        out.error = "template produced no Dockerfile (unsupported)"
        out.duration = time.monotonic() - t0
        return out

    tag = f"cvefactory/{recipe.cve_id.lower()}:vuln"
    rec = _docker_build(cfg, task_dir, tag, use_cache=use_cache,
                        label="engine_vuln_build", cve_id=recipe.cve_id)
    out.build_log_tail = rec.get("log_tail") or ""
    if not rec["success"]:
        out.error = rec.get("first_error") or "docker build failed"
        out.duration = time.monotonic() - t0
        return out

    out.vulnerable_image = tag
    # 端口探测（HTTP 类）
    rt = DockerRuntime(cfg, recipe.cve_id)
    if (recipe.trigger_kind or "http") == "http" or recipe.service_style != "cli":
        out.probe = rt.probe_service(tag, port=int(recipe.port or 18080),
                                     service_file="service.py")
        if not out.probe.get("reachable"):
            # 仍标记构建成功，但记录 ENV 未就绪；上层决定是否 ENV_READY
            out.error = ""
    else:
        out.probe = {"reachable": True, "reason": "non-http skip probe"}

    fixed_tag = f"cvefactory/{recipe.cve_id.lower()}:fixed"
    if build_fixed:
        ctrl_txt = task_dir / "control_image.txt"
        ctrl_image = ""
        if ctrl_txt.is_file():
            ctrl_image = ctrl_txt.read_text(encoding="utf-8").strip()
        if ctrl_image:
            # Jetty/Tomcat：对照版直接构建官方修复镜像标签
            ctrl_dir = task_dir / ".control"
            ctrl_dir.mkdir(parents=True, exist_ok=True)
            for name in ("run-tests.sh", "poc_reference.py", "recipe.json",
                         "solution.sh", "httpd.conf"):
                src = task_dir / name
                if src.is_file():
                    (ctrl_dir / name).write_text(
                        src.read_text(encoding="utf-8"), encoding="utf-8")
            cgi_src = task_dir / "cgi-bin"
            if cgi_src.is_dir():
                cgi_dst = ctrl_dir / "cgi-bin"
                cgi_dst.mkdir(parents=True, exist_ok=True)
                for src in cgi_src.glob("*.cgi"):
                    (cgi_dst / src.name).write_text(
                        src.read_text(encoding="utf-8"), encoding="utf-8")
            port = int(recipe.port or 8080)
            py_setup = (
                "USER root\n"
                "RUN sed -i 's|deb.debian.org|mirrors.tencent.com|g' "
                "/etc/apt/sources.list.d/debian.sources 2>/dev/null || true \\\n"
                "    && apt-get update && apt-get install -y "
                "--no-install-recommends python3 "
                "&& rm -rf /var/lib/apt/lists/*\n"
            )
            if "jetty" in ctrl_image:
                df = (
                    f"FROM {ctrl_image}\n"
                    f"{py_setup}"
                    "COPY . /task/\n"
                    "RUN chmod +x /task/run-tests.sh /task/solution.sh || true\n"
                    f"EXPOSE {port}\n"
                    f'CMD ["java","-jar","/usr/local/jetty/start.jar",'
                    f'"jetty.http.port={port}"]\n'
                )
            elif "httpd" in ctrl_image:
                # Apache httpd 官方镜像：沿用任务包配置/CGI，做 CRLF 清洗
                df = (
                    f"FROM {ctrl_image}\n"
                    f"{py_setup}"
                    "COPY httpd.conf /usr/local/apache2/conf/httpd.conf\n"
                    "COPY cgi-bin/ /usr/local/apache2/cgi-bin/\n"
                    "RUN tr -d '\\r' < /usr/local/apache2/conf/httpd.conf "
                    "> /tmp/c.conf "
                    "&& cat /tmp/c.conf > /usr/local/apache2/conf/httpd.conf "
                    "&& for f in /usr/local/apache2/cgi-bin/*.cgi; do "
                    "tr -d '\\r' < \"$f\" > /tmp/f.cgi "
                    "&& cat /tmp/f.cgi > \"$f\"; done "
                    "&& chmod 755 /usr/local/apache2/cgi-bin/*.cgi\n"
                    "COPY . /task/\n"
                    "RUN chmod +x /task/run-tests.sh /task/solution.sh || true\n"
                    f"EXPOSE {port}\n"
                    'CMD ["httpd-foreground"]\n'
                )
            else:
                df = (
                    f"FROM {ctrl_image}\n"
                    f"{py_setup}"
                    "COPY . /task/\n"
                    "RUN chmod +x /task/run-tests.sh /task/solution.sh || true\n"
                    f"EXPOSE {port}\n"
                    'CMD ["catalina.sh","run"]\n'
                )
            (ctrl_dir / "Dockerfile").write_text(df, encoding="utf-8")
            frec = _docker_build(
                cfg, ctrl_dir, fixed_tag, use_cache=use_cache,
                label="engine_fixed_build", cve_id=recipe.cve_id)
            if frec.get("success"):
                out.fixed_image = fixed_tag
            else:
                out.probe["fixed_build_error"] = (
                    frec.get("first_error") or "control image build failed")
        elif recipe.install_fixed:
            frec = rt.build_fixed(tag, task_dir, fixed_tag)
            if frec.get("success"):
                out.fixed_image = fixed_tag
            else:
                out.probe["fixed_build_error"] = (
                    frec.get("first_error") or "fixed build failed")

    out.ok = True
    out.duration = time.monotonic() - t0
    return out
