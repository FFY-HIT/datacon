# cve-factory（纯 Skill + Cursor）

决策 LLM = **Cursor 底部所选模型**。本仓库只提供 `verify`：构建 `tasks/<CVE>/` 并跑四道门。

## 用法

1. 聊天：`/cve-repro CVE-xxxx`（见 `prompts/cve-repro-agent-only.md`）
2. Agent 写好 `tasks/<CVE>/` 后：

```powershell
.\.venv\Scripts\python cli.py verify --cve CVE-xxxx --mode robust --cursor-model <模型名> --attempt 1
```

失败则在同一对话改 `tasks/`，`--attempt` +1 再 `verify`。

Skill：`.cursor/skills/cve-repro/`

可选 `.env`（镜像加速，**不需要** API Key）：

```
CVE_FACTORY_PIP_INDEX=https://mirrors.tencent.com/pypi/simple/
CVE_FACTORY_DOCKER_HUB_MIRROR=dockerproxy.net
```
