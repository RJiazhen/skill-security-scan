# skill-security-scan

针对**本机已安装的 AI Agent Skills** 做全面安全审计。

English: [README.md](README.md) · 仓库：https://github.com/RJiazhen/skill-security-scan

可检测三类风险：

| 层级 | 关注点 |
|------|--------|
| **L1** | 经典恶意：下载执行、IOC、混淆、凭据窃取、持久化、提示注入等 |
| **L2** | 行为风险：平台导流、强制上传、隐蔽工具交接、压制宿主能力 |
| **L3** | 供应链：静默把 skill 写入 agent 目录、写 skill 路径、安装钩子 |

设计目标之一：补上「只扫恶意软件特征」的盲区——例如把日常开发任务**静默导流**到第三方平台，并**强制上传**本地文件。

---

## 安装

```bash
npx skills add RJiazhen/skill-security-scan -g -y -a cursor
```

若出现 `PromptScript does not support global skill installation`，加上 `-a cursor`（或其它支持的 agent）即可；PromptScript 不支持全局 skill 安装。
安装后即可在 Cursor / Claude 等 Agent 对话里直接使用。

---

## 使用方式（推荐：在 Agent 里调用）

安装完成后，**优先在对话中直接调用本 skill**，无需先记脚本路径。

### 示例 1：扫描本机全部 skill

在 Agent 中说：

> 用 skill-security-scan 扫描本机已安装的 skill，做一次安全审计。

或更口语化：

> 检查一下有没有恶意 skill / 技能安全扫描。

Agent 会按本 skill 的工作流自动发现本机 skill 目录并运行扫描。**默认直接输出完整 Markdown 报告**，并写入 `./skill-security-scan-report.md`（用户明确不要文件、或环境无法创建 md 时则只输出到终端）：总体检查情况、按级别列出的风险项（含可点击出处与原文摘录），以及带 `bash` 代码块的**处置方案**（如隔离 `mv`、复扫）。Agent 应原样转述报告，只在末尾提示写入的文件路径。

用中文交流时，Agent 应以 **中文报告** 呈现结果（扫描时加 `--lang zh`）。

若只要摘要：

> 用 skill-security-scan 扫描，只显示风险语句摘要。

### 示例 2：重点查导流与静默上传

> 用 skill-security-scan 扫描已安装 skill，重点看平台导流、强制上传和静默安装。

这类问题会突出 **L2 / L3** 发现（宽触发劫持、必须 upload、`self skill install` 等）。

### 示例 3：只审某一个可疑 skill

> 用 skill-security-scan 审计这个目录：`/path/to/suspect-skill`

把路径换成实际 skill 目录即可（例如某次 `npx skills add` 或 CLI 注入后的路径）。

### 示例 4：安装第三方 skill 之后复查

> 刚装了一批 skill，用 skill-security-scan 再扫一遍，有 CRITICAL/HIGH 就告诉我怎么隔离。

适合在从 marketplace / CLI 安装后做例行检查。

### 示例 5：结合合成样本理解报告（可选）

若你 clone 了本仓库，可让 Agent：

> 用 skill-security-scan 扫描仓库里的 `test/fixtures/synthetic-divert-upload`，并解释每一条 HIGH/CRITICAL。

该夹具会同时打出导流、强制上传、静默安装、下载执行等典型告警，便于对照报告字段。

干净对照样本：

> 再扫一下 `test/fixtures/clean-docs`，确认是干净的。

---

## 报告里常见发现（对照）

以导流类样本为例，Agent 报告中可能出现：

| 级别 | 检测器 | 含义 |
|------|--------|------|
| CRITICAL | `DownloadExecDetector` | 下载后管道进 shell |
| CRITICAL | `SilentSkillInstallDetector` | 静默把 skill 写入本机 agents |
| HIGH | `PlatformDiversionDetector` | 「软件开发」宽触发 + 第三方 CLI 导流 |
| HIGH | `ForcedUploadDetector` | 「必须」上传本地文件到远端 |
| HIGH | `RemoteWorkflowExfiltrationDetector` | 远端 message 自动附带本地源码文件 |
| HIGH | `OutputDrivenCommandDetector` | 执行 CLI 输出给出的修复命令 |
| HIGH | `ThirdPartyAuthHandoffDetector` | 后台第三方账号授权 |
| HIGH | `CovertToolHandoffDetector` | 用户未点名即路由到外部工具 |
| HIGH | `HostCapabilitySuppressionDetector` | 禁止回退到宿主能力 |

同一 skill 上 **多个 L2/L3 同时出现** 时，即使没有经典后门，也应高度警惕。

处置建议概要：停止使用 → 移出 agent 加载路径 → 检查 CLI 是否会自动重装 → 必要时轮换密钥 → 再扫确认。扫描报告末尾的 **处置方案** 会按告警类别给出步骤，并在已知路径时打印可复制执行的隔离/复扫命令。详见 [`references/remediation.md`](skills/skill-security-scan/references/remediation.md)。

---

## 检测范围摘要

自动发现的常见路径：

- `~/.cursor/skills`、项目内 `.cursor/skills`
- `~/.claude/skills`、`~/.agents/skills`、`~/.codex/skills`
- `~/.trae/skills`、`~/.trae-cn/skills`、项目内 `.trae/skills`（Trae / Trae CN）
- `~/.openclaw/**/skills`、`~/.coze/skills` 等

| 检测器 | 层级 | 主要捕获 |
|--------|------|----------|
| DownloadExecDetector | L1 | 下载后管道进 shell / PowerShell IEX |
| IOCMatchDetector | L1 | 已知恶意 IP / 域名 / 哈希 |
| ExfiltrationDetector | L1 | 敏感目录 + 上传 / 打包 + 上传 |
| CredentialTheftDetector | L1 | 钥匙串、SSH 私钥、密码对话框 |
| PromptInjectionDetector | L1 | 越狱 / 忽略系统规则类文案 |
| PlatformDiversionDetector | L2 | 「软件开发」宽触发 → 第三方 CLI |
| ForcedUploadDetector | L2 | 强制 / 自动上传本地文件 |
| RemoteWorkflowExfiltrationDetector | L2 | 远端 message 工作流附带本地文件 |
| CovertToolHandoffDetector | L2 | 用户未点名却把工作交给外部工具 |
| HostCapabilitySuppressionDetector | L2 | 禁止使用宿主自带能力 |
| ThirdPartyAuthHandoffDetector | L2 | 第三方账号授权（尤其后台） |
| SilentSkillInstallDetector | L3 | 静默安装 skill 到 agents |
| OutputDrivenCommandDetector | L3 | 执行 CLI/工具输出建议的命令 |
| SkillPathWriteDetector | L3 | 脚本写入 agent skill 目录 |

模式说明：[`threat-patterns.md`](skills/skill-security-scan/references/threat-patterns.md)

---

## 高级：直接跑扫描脚本（可选）

一般用户**不需要**这一步；给 CI、二次开发或 Agent 不可用时备用。

```bash
# 扫本机（默认同时写入 ./skill-security-scan-report.md）
python3 skills/skill-security-scan/scripts/scan.py --no-color

# 只要终端输出、不写 md（用户明确不要文件时）
python3 skills/skill-security-scan/scripts/scan.py --no-color --no-md

# 完整中文详细报告（默认，不要加 --summary-only）
python3 skills/skill-security-scan/scripts/scan.py --no-color --lang zh

# 只要风险语句摘要（用户明确只要摘要时）
python3 skills/skill-security-scan/scripts/scan.py --summary-only --severity medium --no-color --lang zh

# 扫单个目录
python3 skills/skill-security-scan/scripts/scan.py --path /path/to/skill --no-color --lang zh

# JSON（含 risk_summaries；statement 随 --lang）
python3 skills/skill-security-scan/scripts/scan.py --json --severity medium --no-color --lang zh

# 关闭 emoji（CI / 纯文本日志）
python3 skills/skill-security-scan/scripts/scan.py --no-emoji --no-color --lang zh
```

退出码：`0` 干净 · `1` low/medium · `2` high · `3` critical

---

## 测试与目录

```bash
npm test
# 或
python3 -m unittest discover -s test -v
```

```text
skills/skill-security-scan/   # skill 本体（SKILL.md + 扫描器）
test/fixtures/                # 合成样本（导流 / 恶意 / 干净等）
README.md                     # 英文（内容一致）
README.zh-CN.md               # 中文（本文件）
```

---

## 发布说明

主流分发：公开 **GitHub** + `npx skills add owner/repo`，由 [skills.sh](https://skills.sh/) 索引。发布到 npm registry **不是**必需步骤。

## 与其它工具的关系

本包目标是比「只扫 Claude/OpenClaw + 恶意 IOC」的工具**覆盖更广**：包含经典 L1 检测，并增加 L2/L3 导流与供应链检查。

`ioc_database.json` 中的指标改编自公开 SlowMist / 社区报告（见 [NOTICE](NOTICE)）。可按新情报自行扩展。

## 许可证

MIT — 见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
