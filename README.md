# 混合主机日志入侵检测

多个服务把日志汇总到一台采集机，字段格式不完全一致。

```
logs/auth.log   862 行（合成，含 3 起真实事件 + 2 组良性相似流量）
labels.json     3 个标注事件
detector/detector.py  关联检测器（格式自适应）
tests/          20 个测试（命中、零误报、方言兼容、needs_review）
findings.json   检测器输出
```

## Run

```bash
python -m pytest tests -q
python detector/detector.py logs/auth.log findings.json
```

## 为什么不能按固定列切分

采集机上的混合日志在**列层面没有统一语义**：

- 时间戳有 BSD（`Oct 01 06:35:29`）与 RFC5424（`2026-10-01T06:35:29+00:00`）两种；
- 程序名后 PID 括号可有可无（`sshd[10000]` vs `sudo:`）；
- nginx 请求串带引号且内部含空格，UA 字符串空格数不固定；
- dnsmasq / BIND / Windows DNS 的字段顺序完全不同；
- 文件为 CRLF 行尾。

检测器因此不做任何按位置的列切分，而是三层对齐：

1. **信封层**：用一个宽容正则统一抽取 时间戳 / 主机 / 程序 / PID / 消息体；
2. **分发层**：按程序名（语义来源）路由到各自的消息体正则，全部使用**命名分组**；
3. **归一化层**：所有行落到同一个 `Event` 模式，关联规则只消费归一化字段。

识别不了的行不会被硬塞进某个字段，而是进入 `needs_review`（`reason=unparsed`），
让格式漂移可见。

## 三条关联规则

| rule | 关联逻辑（均要求时间窗口 + 实体一致） |
|---|---|
| `privilege_escalation` | 非 root 用户 sudo 起交互式 root shell（bash/sh/su…），同主机 10 分钟内出现 root 登录；IP 能对上则 `ip_link_confirmed=true`，对不上则降级为置信度说明而非漏报 |
| `dns_tunnel` | 同一客户端对**同一隧道域**（查询名最长公共后缀）在 15 分钟窗口内发出 ≥8 条唯一、超长（≥20 字符）、高熵（≥3.5）子域查询；分散在不同子域的随机名按 CDN 噪声忽略 |
| `webshell` | 同一 IP 30 分钟内先命中上传端点（`/upload.php` 等，HTTP <400），再访问 `/uploads/` 下可执行脚本且带 `cmd/exec/...` 命令参数且成功 |

## 输出契约（findings.json）

```json
{
  "findings": [
    {
      "rule": "dns_tunnel",
      "severity": "high",
      "first_seen": "Oct 01 06:40:07",
      "last_seen": "Oct 01 06:41:00",
      "entities": {"ip": "...", "tunnel_zone": "...", "...": "..."},
      "evidence": [ {"line": 843, "timestamp": "...", "event": "dns", "...": "..."} ],
      "summary": "一句话结论",
      "alignment": "格式不一致时该规则靠什么对齐"
    }
  ],
  "needs_review": [
    {"rule": "...", "reason": "inconclusive|unparsed", "missing": "缺哪类信息", "...": "..."}
  ]
}
```

每条告警给出时间窗口（`first_seen/last_seen` + 行号范围）、实体（用户 / IP /
主机 / 域 / 路径）和有序事件序列 `evidence`。证据不足或方言无法解析时进入
`needs_review` 并写明具体缺失的信息，绝不猜测成告警。

## 标注事件与良性流量

| kind | 说明 |
|---|---|
| `privilege_escalation` | 提权 |
| `dns_tunnel` | DNS 隧道外传 |
| `webshell` | 上传后执行 webshell |

良性相似流量（`ops` 三次失败后公钥成功登录；`10.20.1.88` 两次 403 探测）
不产生任何告警或 review 项——测试 `test_benign_lookalikes_zero_false_positives`
固化了这一保证。
