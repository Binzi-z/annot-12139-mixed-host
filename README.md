# 12139 — Python 命令注入：跨模块污点分析 + SARIF

红队从三个 Python 服务各拿到一个 shell，手法都是命令注入；修复全是加引号。
本仓库是重做分析器的语料与起点：**只准用语法解析库自建 CFG 与污点状态，现成规则引擎不许碰**。

## 语料构成

```
services/           Flask 路由 / Celery 任务 / CLI 入口（真实链路都在这里）
  gateway/          diag.py ops.py users.py monitor.py（monitor 全是良性调用）
  jobs/             tasks_maintenance.py tasks_sync.py
  admin/console.py
  reports/render.py
  ingest/pipeline.py
  scripts/health.py 良性调用
  cli/entry.py
lib/                shellwrap.py（shell 包装）cmdutil.py（check_output 包装）
                    templating.py（命令模板渲染）decorators.py（audited/require_role）
                    sanitizers.py celery_app.py
templates/          8 个命令模板（.j2，用 str.format 占位）
config/sanitizers.json  可配置的 sanitizer / shell_wrapper / safe_wrapper / 模板渲染器白名单
filler/             380 个模块、约 19 万行的业务占位代码（纯函数，无 sink）
```

合计 **397 个 .py、196,067 行**（`filler/` 就是题面里「20 万行全量」的那片代码；
另有一批常量 `subprocess.run` 属于良性，报了就是误报）。

## 标注（labels.json，50 条）

| variant | 条数 | 落点形态 |
|---|---:|---|
| `concat_shell` | 19 | 字符串拼接 + `subprocess.run(shell=True)` / `os.system` / `os.popen` |
| `arglist_misuse` | 7 | `["/bin/sh","-c", 拼接]`，或用户输入被当成 `argv[0]` |
| `shell_wrapper` | 8 | 经 `lib/shellwrap.run_shell`、`lib/cmdutil.critical_run` 进 shell |
| `template_rendered` | 12 | `lib/templating.render_cmd/render_inline` 渲染出的命令再执行 |
| `closure` | 2 | 闭包捕获的参数进 `os.system` |
| `class_attr` | 2 | 参数存进实例属性 `self.cmd`，`run()` 时进 shell |

| source | 条数 |
|---|---:|
| Flask 路由参数（args/form/json） | 28 |
| Celery 任务参数 | 11 |
| 环境变量（`os.environ` / `os.getenv`） | 11 |

传播面：跨模块（services → lib）、穿过装饰器（`@audited` / `@require_role` 转发 `*args, **kwargs`）、
闭包、实例属性、模板渲染函数返回值。每条标注带 `file`/`line`、`variant`、`source`、
`entry`（污点入口）、`path`（传播路径）与 `evidence`。

**finding 的 `file`/`line` 指向污点实际到达的执行调用行**；`lib/` 里被多个调用点共用的
包装函数实现行（`subprocess.call(cmd, shell=True)`）不算——那里没有「哪条链路」的信息。

## 良性注入点（报了就是误报）

`services/gateway/monitor.py`、`services/scripts/health.py`、`lib/` 的包装实现、`filler/` 里的探针：

- 常量命令：`subprocess.run("df -h", shell=True)`、`os.popen("date -u")`
- argv 列表：`subprocess.run(["/usr/bin/uptime"])`、`["systemctl", "is-active", svc]`（svc 来自字典白名单）
- 净化后：`shlex.quote`、`os.path.basename`、`int()`、`allow_enum`
- 安全包装：`shellwrap.run_argv`、`cmdutil.safe_run`（`shell=False`）

`sanitizer 白名单` 在 `config/sanitizers.json`，可以增删（题目要求可配置）。

## 基线（baseline/scan.py）

正则扫「命令执行 API」，不看参数是否可控：`subprocess.*` / `os.system` / `os.popen` /
`shellwrap.*` / `cmdutil.*` 出现即报。召回高、误报明显（良性调用与包装实现全报）。

实测（扫描 196,067 行，约 0.4 秒）：

```
labels=50 findings=81 TP=50 FP=31 FN=0
recall=100.0% precision=61.7% false_positive_rate=38.3%
```

## 题面的效果指标（本仓库给出的起点）

- 50 条样本：召回 ≥85%、误报 ≤15%（基线 100% / 38.3%，要压下去只能靠真污点分析）
- 20 万行全量 <3 分钟、增量 <15 秒、增量与全量一致（本仓库 196k 行可直接压测）
- 产出 SARIF，CI 里新增违规必须红灯（`eval.py` 直接吃 SARIF）

## 跑法

```powershell
python baseline/scan.py | Out-File -Encoding utf8 o.json
python eval.py o.json
python -m pytest tests -q
```

`eval.py` 同时接受 `findings.json` 与 SARIF 2.1.0。
运行时依赖（flask/celery）**不需要安装**：本题只做静态分析，`ast` 解析不需要 import 执行。

## 评测口径（eval.py）

- 静态类标注（只有 file/line）：文件相同且行号差 ≤2（允许报在拼接行或调用行）。
- `needs_review` 不计分；一个标注只算命中一次，重复上报同一处算误报。
- rule 名称建议用 `command_injection`（`cmd_injection`/`CWE-78` 等别名也认）。
- 分析范围：`services/`、`lib/`、`filler/`（`baseline/`、`tools/`、`tests/` 不参与）。

## 重造语料

```powershell
python tools/make_corpus.py     # 固定 seed，重跑得到同一份代码与 labels.json（约 20 秒）
```
