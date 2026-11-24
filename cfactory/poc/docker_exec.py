"""在 factory 产出的 vulnerable / fixed 镜像里执行 PoC。"""
from __future__ import annotations

import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from .models import ExecResult, PoC


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str, float]:
    t0 = time.monotonic()
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 5,
            errors="replace")
        return p.returncode, p.stdout or "", p.stderr or "", time.monotonic() - t0
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        err = (e.stderr or "") if isinstance(e.stderr, str) else ""
        return -1, out, err + f"\nTIMEOUT after {timeout}s", time.monotonic() - t0


class DockerPoCExecutor:
    def __init__(self, *, vulnerable_image: str, fixed_image: str = "",
                 port: int = 18080, network: str = "none",
                 poc_dir: str | Path = "", docker: str = "docker",
                 timeout: int = 180) -> None:
        self.vuln = vulnerable_image
        self.fixed = fixed_image
        self.port = int(port or 18080)
        self.network = network or "none"
        self.docker = docker
        self.timeout = timeout
        self.poc_dir = Path(poc_dir) if poc_dir else Path("output") / "poc_runs"
        self.poc_dir.mkdir(parents=True, exist_ok=True)
        self.count = 0
        self.log: list[dict[str, Any]] = []

    def _exec(self, tag: str, poc: PoC) -> ExecResult:
        if not tag:
            return ExecResult(exit_code=-1, stderr="no image tag", backend="docker-poc")
        self.count += 1
        suffix = Path(poc.filename or "poc.py").suffix or ".py"
        fname = f"poc_{self.count:02d}{suffix}"
        host = self.poc_dir / fname
        host.write_text(poc.code, encoding="utf-8")
        name = "cvefactory_poc_" + uuid.uuid4().hex[:10]
        run_cmd = [self.docker, "run", "-d", "--rm", "--name", name,
                   "--network", self.network,
                   "-v", f"{host.resolve()}:/task/{fname}:ro", tag]
        rc, out, err, dur = _run(run_cmd, 90)
        if rc != 0:
            rec = ExecResult(exit_code=rc, stdout=out, stderr=err, duration=dur,
                             backend="docker-poc", image=tag)
            self.log.append(rec.to_dict())
            return rec
        if self.port > 0:
            probes = [
                f"bash -c 'echo >/dev/tcp/127.0.0.1/{self.port}'",
                (
                    "python3 -c \"import socket;s=socket.socket();s.settimeout(0.3);"
                    f"s.connect(('127.0.0.1',{self.port}));s.close()\""
                ),
                (
                    "python -c \"import socket;s=socket.socket();s.settimeout(0.3);"
                    f"s.connect(('127.0.0.1',{self.port}));s.close()\""
                ),
            ]
            for _ in range(40):
                ok = False
                for probe in probes:
                    prc, _, _, _ = _run(
                        [self.docker, "exec", name, "sh", "-c", probe], 10)
                    if prc == 0:
                        ok = True
                        break
                if ok:
                    break
                time.sleep(0.4)
        lang = (poc.language or "python").lower()
        if lang.startswith(("js", "node")):
            poc_cmd = ["node", f"/task/{fname}"]
        else:
            # python3 优先（Jetty/Tomcat 镜像常只装了 python3）
            poc_cmd = ["sh", "-c",
                       f"python3 /task/{fname} 2>/dev/null || python /task/{fname}"]
        erc, eout, eerr, edur = _run(
            [self.docker, "exec", name, *poc_cmd], self.timeout)
        _run([self.docker, "rm", "-f", name], 20)
        rec = ExecResult(exit_code=erc, stdout=eout, stderr=eerr,
                         duration=edur + dur, timed_out=(erc == -1),
                         backend="docker-poc", image=tag)
        self.log.append(rec.to_dict())
        return rec

    def run_vulnerable(self, poc: PoC) -> ExecResult:
        return self._exec(self.vuln, poc)

    def run_fixed(self, poc: PoC) -> ExecResult | None:
        if not self.fixed:
            return None
        return self._exec(self.fixed, poc)
