"""真实 Docker 运行时：构建镜像、容器内执行客观检查脚本、执行 PoC。

论文中的 Agent 是 Claude Code 会话，可自主执行 Docker 命令；本实现用
「LLM 生成文件 + 编排器调用 Docker CLI」复现同样的步骤，所有判定仍由
客观脚本（checks.py）而不是 Agent 自评给出。
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import signal
import subprocess
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any

from .config import Config


def rewrite_hub_image(image: str, mirror: str) -> str:
    """把 Docker Hub 官方短名改写到镜像代理，避免直连 registry-1.docker.io。

    - ``python:3.11-slim`` -> ``<mirror>/library/python:3.11-slim``
    - ``docker.io/library/python:3.11-slim`` 同上
    - 本地/项目镜像（如 ``cvefactory/foo:tag``、已带 registry host）原样返回
    - ``sha256:...`` 本地 image id 绝不改写（否则对照构建会失败）
    """
    mirror = (mirror or "").strip().rstrip("/")
    image = (image or "").strip()
    if not mirror or not image:
        return image
    # 本地 digest / image id
    if image.startswith("sha256:") or image.startswith("sha256@"):
        return image
    if len(image) == 64 and all(c in "0123456789abcdef" for c in image):
        return image
    if image.startswith(mirror + "/"):
        return image
    if image.startswith("docker.io/library/"):
        return f"{mirror}/library/{image[len('docker.io/library/'):]}"
    if image.startswith("docker.io/"):
        rest = image[len("docker.io/"):]
        # 仅官方单段名；org/name 留给显式配置，避免误伤本地命名空间
        if "/" not in rest.split(":", 1)[0]:
            return f"{mirror}/library/{rest}"
        return image
    # repo path without tag (avoid treating "python:3.11-slim" dots as a host)
    repo = image.split(":", 1)[0]
    if "/" in repo:
        first = repo.split("/", 1)[0]
        # real registry host: ghcr.io/..., localhost:5000/...
        if "." in first or ":" in first:
            return image
        return image  # local/project namespaces (cvefactory/...)
    # official short name only: python:3.11-slim
    return f"{mirror}/library/{image}"


def _image_exists_locally(docker: str, image: str) -> bool:
    if not image:
        return False
    rc, _, _, _ = _run([docker, "image", "inspect", image], 20)
    return rc == 0


def _canonical_hub_short(image: str, mirror: str) -> str:
    """dockerproxy.net/library/jetty:x -> jetty:x；其它原样。"""
    mirror = (mirror or "").strip().rstrip("/")
    image = (image or "").strip()
    if mirror and image.startswith(mirror + "/library/"):
        return image[len(mirror) + len("/library/"):]
    if image.startswith("docker.io/library/"):
        return image[len("docker.io/library/"):]
    return image


def rewrite_dockerfile_from(text: str, mirror: str, *,
                            docker: str = "docker",
                            prefer_local: bool = True) -> str:
    """改写 Dockerfile 中所有 FROM 行的镜像引用。

    若本地已有官方短名（如 ``jetty:9.4.51-jre11``），则不改写到镜像代理，
    避免 dockerproxy TLS 超时；已写成代理名的也会回退成本地短名。
    """
    if not (mirror or "").strip() and not prefer_local:
        return text

    def _sub(m: re.Match[str]) -> str:
        prefix, img, rest = m.group(1), m.group(2), m.group(3) or ""
        short = _canonical_hub_short(img, mirror)
        if prefer_local and (
                _image_exists_locally(docker, short)
                or _image_exists_locally(docker, img)):
            # 优先用本地短名，避免走坏掉的代理
            return f"{prefix}{short}{rest}"
        if not (mirror or "").strip():
            return f"{prefix}{img}{rest}"
        return f"{prefix}{rewrite_hub_image(img, mirror)}{rest}"

    return re.sub(
        r"^(FROM\s+(?:--\S+\s+)*)(\S+)(.*)$",
        _sub,
        text,
        flags=re.MULTILINE | re.IGNORECASE,
    )


def ensure_dockerfile_copy_task(text: str) -> str:
    """强制 Dockerfile 含 ``COPY . /task/``，避免只拷 service.py 导致缺测试。

    - 已有 ``COPY . /task/``：原样返回
    - 仅有 ``COPY service.py ...`` 等窄拷贝：在其后插入整树 COPY
    - 完全没有 COPY：在 WORKDIR 或 RUN 安装后、CMD 前插入
    """
    text = text or ""
    if re.search(r"^\s*COPY\s+\.\s+/task/?\s*$", text, re.I | re.M):
        return text
    insert = "COPY . /task/\n"
    # 窄拷贝 service / 单文件：紧接其后补整树
    m = re.search(
        r"(^\s*COPY\s+\S+\s+/task/\S*\s*$)", text, re.I | re.M)
    if m:
        pos = m.end()
        return text[:pos] + "\n" + insert + text[pos:].lstrip("\n")
    m_wd = re.search(r"(^\s*WORKDIR\s+/task/?\s*$)", text, re.I | re.M)
    if m_wd:
        pos = m_wd.end()
        return text[:pos] + "\n" + insert + text[pos:].lstrip("\n")
    m_cmd = re.search(r"^\s*CMD\b", text, re.I | re.M)
    if m_cmd:
        return text[:m_cmd.start()] + insert + text[m_cmd.start():]
    return text.rstrip() + "\n" + insert


def _kill_tree(p: subprocess.Popen) -> None:
    """跨平台杀掉子进程整棵进程树（Windows 用 taskkill /T，Unix 用进程组）。"""
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(p.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15)
        else:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except Exception:  # noqa: BLE001
        try:
            p.kill()
        except Exception:  # noqa: BLE001
            pass


def _run(cmd: list[str], timeout: int, cwd: str | None = None,
         env: dict[str, str] | None = None) -> tuple[int, str, str, float]:
    t0 = time.monotonic()
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env,
                         errors="replace", start_new_session=(os.name != "nt"))
    try:
        out, err = p.communicate(timeout=timeout + 15)
        duration = time.monotonic() - t0
        out, err = out or "", err or ""
        return p.returncode, out, err, duration
    except subprocess.TimeoutExpired:
        _kill_tree(p)
        out, err = p.communicate()
        return -1, out or "", (err or "") + f"\nTIMEOUT after {timeout}s", time.monotonic() - t0


def context_digest(workdir: Path) -> str:
    """构建上下文摘要（归一化 mtime/uid/gid，只反映内容）。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for p in sorted(workdir.rglob("*")):
            if not p.is_file() or p.name == "agent-res.xml":
                continue
            info = tf.gettarinfo(str(p), arcname=str(p.relative_to(workdir)))
            info.mtime, info.uid, info.gid = 0, 0, 0
            info.uname, info.gname = "", ""
            with p.open("rb") as f:
                tf.addfile(info, f)
    return "sha256:" + hashlib.sha256(buf.getvalue()).hexdigest()


class DockerRuntime:
    def __init__(self, cfg: Config, cve_id: str) -> None:
        self.cfg = cfg
        self.cve_id = cve_id
        self.logs_dir = Path(cfg.logs_dir)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.poc_dir = Path(cfg.output_dir) / "poc" / cve_id
        self.poc_dir.mkdir(parents=True, exist_ok=True)
        self.exec_count = 0

    def log(self, label: str, text: str) -> Path:
        p = self.logs_dir / f"{self.cve_id}_{label}.log"
        p.write_text(text, encoding="utf-8")
        return p

    # ------------------------------------------------------------------ #
    def build(self, task_dir: Path, tag: str, label: str) -> dict[str, Any]:
        # 构建前：强制 COPY . /task/ + 改写 FROM（避免缺测试 / Hub TLS 超时）
        df = task_dir / "Dockerfile"
        if df.is_file():
            original = df.read_text(encoding="utf-8", errors="replace")
            rewritten = ensure_dockerfile_copy_task(original)
            rewritten = rewrite_dockerfile_from(
                rewritten, self.cfg.docker_hub_mirror or "",
                docker=self.cfg.docker, prefer_local=True)
            if rewritten != original:
                df.write_text(rewritten, encoding="utf-8")
        env = dict(os.environ)
        env["DOCKER_BUILDKIT"] = "1"
        # 不传 --pull：优先用本地/镜像代理已拉好的基础镜像，避免再探 docker.io
        cmd = [self.cfg.docker, "build", "--no-cache", "--progress=plain",
               "--platform", self.cfg.target_platform, "-t", tag, "."]
        rc, out, err, dur = _run(cmd, self.cfg.max_build_seconds,
                                 cwd=str(task_dir), env=env)
        log = out + "\n" + err
        self.log(label, log)
        rec: dict[str, Any] = {
            "success": rc == 0, "tag": tag, "label": label,
            "exit_code": rc, "duration": dur,
            "context_digest": context_digest(task_dir),
            "log_path": str(self.logs_dir / f"{self.cve_id}_{label}.log"),
            "log_tail": log[-2500:],
        }
        if rec["success"]:
            rec["image_id"] = self._inspect(tag, "{{.Id}}")
            rec["created"] = self._inspect(tag, "{{.Created}}")
        else:
            m = re.search(r"(?i)(error|failed|fatal|not found|no such)[^\n]{0,300}", log)
            rec["first_error"] = m.group(0) if m else log[-500:]
        return rec

    def _inspect(self, tag: str, fmt: str) -> str:
        rc, out, _, _ = _run([self.cfg.docker, "image", "inspect",
                              "--format", fmt, tag], 30)
        return out.strip() if rc == 0 else ""

    # ------------------------------------------------------------------ #
    def run_tests(self, tag: str, apply_fix: bool = False,
                  label: str = "run_tests") -> dict[str, Any]:
        """在容器内执行 run-tests.sh（客观检查脚本），返回 stdout/stderr/退出码。"""
        cmd = [self.cfg.docker, "run", "--rm",
               "--network", self.cfg.network_mode,
               "--platform", self.cfg.target_platform]
        if apply_fix:
            cmd += ["-e", "FACTORY_APPLY_FIX=1"]
        cmd += [tag, "sh", "/task/run-tests.sh"]
        rc, out, err, dur = _run(cmd, self.cfg.max_run_seconds)
        self.log(label, (out + "\n" + err))
        return {"exit_code": rc, "stdout": out, "stderr": err,
                "duration": dur, "timed_out": rc == -1,
                "backend": "cve-factory-docker", "command": " ".join(cmd)}

    def smoke_run_tests(self, tag: str) -> dict[str, Any]:
        """CLI / library_api 就绪检查：镜像能启动且 run-tests.sh 可执行。"""
        cmd = [self.cfg.docker, "run", "--rm",
               "--network", self.cfg.network_mode,
               "--platform", self.cfg.target_platform, tag,
               "sh", "-c",
               "test -f /task/run-tests.sh && test -x /task/run-tests.sh "
               "|| chmod +x /task/run-tests.sh; "
               "head -c 1 /task/run-tests.sh >/dev/null"]
        rc, out, err, dur = _run(cmd, 60)
        return {"ok": rc == 0, "exit_code": rc, "stdout": out,
                "stderr": err, "duration": dur}

    # ------------------------------------------------------------------ #
    def probe_service(self, tag: str, port: int = 18080,
                      service_file: str = "service.py") -> dict[str, Any]:
        """构建健康检查：在容器里真实启动服务并探测声明端口是否可达。

        补齐「docker build 成功 ≠ 环境正确」的缺口：服务没起来、端口写错、
        启动命令失败都会在这里被客观抓出来。端口与启动文件来自 EnvSpec。
        """
        name = "cvefactory_probe_" + uuid.uuid4().hex[:8]
        run_cmd = [self.cfg.docker, "run", "-d", "--rm", "--name", name,
                   "--network", self.cfg.network_mode,
                   "--platform", self.cfg.target_platform, tag]
        run_cmd[2:2] = self.cfg.run_extra_args()
        rc, out, err, _ = _run(run_cmd, 60)
        if rc != 0:
            return {"reachable": False, "exit_code": rc,
                    "stdout": "", "stderr": err[-800:],
                    "reason": "container failed to start"}
        # 不依赖镜像内 python（Jetty/Tomcat 官方镜像通常无 python）
        port_i = int(port)
        probes = [
            f"bash -c 'echo >/dev/tcp/127.0.0.1/{port_i}'",
            f"sh -c 'cat </dev/null >/dev/tcp/127.0.0.1/{port_i}'",
            (
                "python -c \"import socket;s=socket.socket();s.settimeout(0.3);"
                f"s.connect(('127.0.0.1',{port_i}));s.close()\""
            ),
            f"wget -q -O- http://127.0.0.1:{port_i}/ >/dev/null",
            f"curl -sf http://127.0.0.1:{port_i}/ >/dev/null",
        ]
        reachable, attempts = False, 0
        for _ in range(40):
            attempts += 1
            for probe in probes:
                prc, _, _, _ = _run(
                    [self.cfg.docker, "exec", name, "sh", "-c", probe], 10)
                if prc == 0:
                    reachable = True
                    break
            if reachable:
                break
            time.sleep(0.4)
        # 版本可核对（python 镜像才有；失败忽略）
        vrc, vout, _, _ = _run(
            [self.cfg.docker, "exec", name, "sh", "-c",
             "python -c \"import importlib.metadata as m;"
             "print('\\n'.join(sorted(d.metadata['Name']+'=='+d.version "
             "for d in m.distributions() if d.metadata.get('Name')))[:1500])\" "
             "2>/dev/null || true"], 20)
        _run([self.cfg.docker, "rm", "-f", name], 20)
        return {"reachable": reachable, "exit_code": 0 if reachable else 1,
                "stdout": (vout or "") if vrc == 0 else "",
                "probe_attempts": attempts, "port": port,
                "service_file": service_file,
                "installed_packages_sample": (vout or "")[-1200:],
                "reason": "service reachable on declared port" if reachable
                          else "service never became reachable"}

    # ------------------------------------------------------------------ #
    def build_fixed(self, vulnerable_tag: str, task_dir: Path,
                    fixed_tag: str) -> dict[str, Any]:
        """由漏洞镜像 + solution.sh 生成对照镜像。

        不走 Dockerfile ``FROM``（BuildKit+代理会误拉远程）。
        用临时 sleep 容器执行 solution，commit 时恢复原镜像 CMD/ENTRYPOINT。
        """
        import json as _json
        sol = task_dir / "solution.sh"
        if not sol.is_file():
            return {"success": False, "tag": fixed_tag, "label": "fixed_build",
                    "first_error": "missing solution.sh"}
        # 读取原镜像启动配置，commit 时写回
        irc, iout, _, _ = _run(
            [self.cfg.docker, "image", "inspect", vulnerable_tag], 30)
        # 用原镜像 CMD 启动（长期服务），exec 打补丁后 commit，保留原 ENTRYPOINT/CMD
        name = "cvefactory_fix_" + uuid.uuid4().hex[:10]
        t0 = time.monotonic()
        run_cmd = [self.cfg.docker, "run", "-d", "--name", name,
                   "--network", "bridge",
                   "--platform", self.cfg.target_platform,
                   "-v", f"{sol.resolve()}:/tmp/solution.sh:ro",
                   vulnerable_tag]
        run_cmd[2:2] = self.cfg.run_extra_args()
        rc, out, err, _ = _run(run_cmd, 90)
        if rc != 0:
            return {"success": False, "tag": fixed_tag, "label": "fixed_build",
                    "exit_code": rc, "first_error": (err or out)[-800:],
                    "duration": time.monotonic() - t0}
        # 等服务进程起来再 exec
        time.sleep(1.0)

        sol_txt = sol.read_text(encoding="utf-8", errors="replace")
        # Windows 检出常为 CRLF，会导致 `set: Illegal option -`；统一写成 LF
        sol_txt = sol_txt.replace("\r\n", "\n").replace("\r", "\n")
        if "pip install" in sol_txt and self.cfg.pip_index_url:
            sol_txt = sol_txt.replace(
                "pip install",
                f"pip install -i {self.cfg.pip_index_url}", 1)
        # 始终在容器内重写 solution，避免 bind-mount 的 CRLF
        cmd = (
            "cat > /tmp/solution_run.sh <<'EOS'\n"
            f"{sol_txt}\nEOS\n"
            "chmod +x /tmp/solution_run.sh\n"
            "sh /tmp/solution_run.sh"
        )
        erc, eout, eerr, _ = _run(
            [self.cfg.docker, "exec", name, "sh", "-c", cmd],
            self.cfg.max_build_seconds)
        log = (eout or "") + "\n" + (eerr or "")
        self.log("fixed_build", log)
        if erc != 0:
            _run([self.cfg.docker, "rm", "-f", name], 30)
            return {"success": False, "tag": fixed_tag, "label": "fixed_build",
                    "exit_code": erc, "first_error": log[-800:],
                    "duration": time.monotonic() - t0, "log_tail": log[-2500:],
                    "method": "docker-commit"}

        # 显式写回原 CMD，并清空被污染的 ENTRYPOINT
        cfg0 = {}
        if irc == 0:
            try:
                cfg0 = (_json.loads(iout)[0].get("Config") or {})
            except Exception:  # noqa: BLE001
                cfg0 = {}
        cmd_json = _json.dumps(cfg0.get("Cmd") or ["python", "/task/service.py"])
        commit_cmd = [
            self.cfg.docker, "commit",
            "--change", "ENTRYPOINT []",
            "--change", f"CMD {cmd_json}",
            name, fixed_tag,
        ]
        crc, cout, cerr, _ = _run(commit_cmd, 120)
        _run([self.cfg.docker, "rm", "-f", name], 30)
        ok = crc == 0
        return {
            "success": ok, "tag": fixed_tag, "label": "fixed_build",
            "exit_code": crc, "duration": time.monotonic() - t0,
            "method": "docker-commit",
            "log_tail": ((cout or "") + "\n" + (cerr or "") + "\n" + log)[-2500:],
            "first_error": "" if ok else (cerr or cout or log)[-800:],
        }

    # ------------------------------------------------------------------ #
    def run_poc(self, tag: str, code: str, filename: str,
                language: str, port: int = 18080) -> dict[str, Any]:
        """把 PoC 注入已生成环境执行：后台启动服务 -> exec PoC -> 清理容器。

        port 由交接包 environment.service_port 提供，不再硬编码。
        """
        self.exec_count += 1
        suffix = Path(filename or "poc.py").suffix
        if suffix not in (".py", ".js", ".go"):
            suffix = {"javascript": ".js", "go": ".go"}.get(language, ".py")
        fname = f"poc_{self.exec_count:02d}{suffix}"
        host_path = self.poc_dir / fname
        host_path.write_text(code, encoding="utf-8")
        (self.poc_dir / ("poc.js" if suffix == ".js" else
                         "poc.go" if suffix == ".go" else "poc.py")).write_text(
            code, encoding="utf-8")

        name = "cvefactory_" + uuid.uuid4().hex[:10]
        run_cmd = [self.cfg.docker, "run", "-d", "--rm", "--name", name,
                   "--network", self.cfg.network_mode,
                   "--platform", self.cfg.target_platform,
                   "-v", f"{host_path}:/task/{fname}:ro", tag]
        rc, out, err, dur = _run(run_cmd, 90)
        if rc != 0:
            return {"exit_code": rc, "stdout": out, "stderr": err,
                    "duration": dur, "timed_out": False,
                    "backend": "cve-factory-docker",
                    "command": " ".join(run_cmd)}
        # 等待容器内服务就绪（loopback，客观探测，不依赖 PoC 自身重试）
        probe = ("python -c \"import socket;"
                 f"s=socket.socket();s.settimeout(0.3);"
                 f"s.connect(('127.0.0.1',{int(port)}));s.close()\"")
        for _ in range(30):
            prc, _, _, _ = _run([self.cfg.docker, "exec", name, "sh", "-c", probe], 10)
            if prc == 0:
                break
            time.sleep(0.3)

        if language.startswith(("js", "java", "node", "ecma")):
            poc_cmd = ["node", f"/task/{fname}"]
        elif language.startswith("go"):
            poc_cmd = ["go", "run", f"/task/{fname}"]
        else:
            poc_cmd = ["python", f"/task/{fname}"]
        exec_cmd = [self.cfg.docker, "exec", name, *poc_cmd]
        erc, eout, eerr, edur = _run(exec_cmd, self.cfg.max_run_seconds)
        _run([self.cfg.docker, "rm", "-f", name], 20)
        return {"exit_code": erc, "stdout": eout, "stderr": eerr,
                "duration": edur + dur, "timed_out": erc == -1,
                "backend": "cve-factory-docker",
                "command": " ".join(exec_cmd)}
