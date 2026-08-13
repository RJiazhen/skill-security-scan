# Review heuristic hits before reporting

The Python scanner is a **candidate finder**. It matches routing / upload /
install *language*. It does not know whether a named tool is the host’s own
capability or another product. Do **not** grow vendor or tool-name lists in
`scan.py` to paper over that. Apply the rules below to every L2/L3 hit
before the user sees the report.

Read each item’s **出处** file around the cited line. Decide from that
context, not from the scanner’s 说明 draft.

## Destination test (covert handoff / platform diversion)

Ask one question: **does this instruction send ordinary user work into a
different execution environment than the current host agent?**

| Keep | Drop |
|------|------|
| Work moves to another **product, cloud agent, vendor CLI, or peer agent** without the user naming that destination | Work stays on a **host built-in** tool, model, or CLI that this agent already ships |
| The skill *activates* that external path for a broad intent (“做软件”, “改代码”, “生成一批图”) | The line is a **guardrail**: stay on the built-in path; do not silently switch; ask before changing model/CLI |
| Fallback to an external tool happens even when the user never asked for it | Optional path that runs only after the user names the other tool or model |

“Built-in” is whatever **this host** already provides (image generation,
search, its own CLI wrappers, and so on). Do not keep an allowlist of
names. If the surrounding text says built-in / host / native / 自带 / 宿主,
treat it as in-agent. If it says another product, cloud, vendor CLI, or
peer agent, treat it as external.

A sentence that contains “silently switch” or “without explicitly asking”
is **not** automatically a handoff. Those phrases also appear in host
guardrails that *forbid* leaving the built-in path.

## Concrete 说明 / Note

The scanner sentence is a draft. Rewrite it from the source.

- Name the **actual destination** (command, product, or platform) and the
  **user-visible effect**.
- Do not recopy the excerpt. Do not say only “交给外部工具 / hands work to
  an external tool” when the source already names the destination.
- If the skill launches an external coding CLI for ordinary software-project
  work (网页 / App / 小程序 / “开发、修改软件”) without the user naming that
  CLI, say so: it may invoke that CLI to start the software project on the
  other platform.
- If you dropped the item as a host guardrail, do not mention it in the
  report. Do not narrate the filter.

## Other categories

Use the same source-first pass:

- **Forced upload / remote workflow**: keep when local files leave the
  machine as a required step; drop when upload is optional and only after
  the user asked to share.
- **Host suppression**: keep when the skill forbids the host’s own tools so
  the vendor path is the only one; drop when it only prefers a built-in
  tool over a worse built-in fallback.
- **Silent install / path write**: keep when skills are written into agent
  directories without review; drop when the text only *documents* those
  directories.

## After review

1. Recalculate 风险级别统计 / severity totals.
2. Remove empty severity headings.
3. Keep 出处 links and 原文摘录 verbatim for items you keep.
4. Drop remediation subsections for skills that no longer have findings.
5. Overwrite the markdown report file with this reviewed text, then paste
   that file. No preamble about filtering or truncation.
