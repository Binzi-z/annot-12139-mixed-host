# taint_sa 设计说明：跨过程污点分析如何在合并前拦住命令注入

只依赖 Python 标准库 `ast` 做语法解析，CFG、污点状态、过程间摘要、SARIF 序列化
全部自建；不使用任何现成规则引擎（`tests/test_taint_sa.py::test_only_ast_dependency`
会扫描包内 import 强制这一约束）。

## 1. 总体架构

```
源码 ──ast.parse──> ModuleRepo（import 解析、模块全限定名索引）
                        │
              FunctionRegistry（函数/方法/嵌套函数/类发现）
                        │
   ┌────────────────────┴────────────────────┐
   │ 阶段 1：摘要构建（marker 探针，一次/函数） │
   │  FunctionAnalyzer: 自建 CFG + worklist    │
   │  不动点，产出 FunctionSummary              │
   └────────────────────┬────────────────────┘
                        │  ret_masks / self_writes / sinks(marker 掩码)
   ┌────────────────────┴────────────────────┐
   │ 阶段 2：入口重放（真实 source 实例化）     │
   │  Flask 路由 / Celery 任务 / CLI 入口       │
   │  调用点用实参污点替换 marker，在执行行上报  │
   └────────────────────┬────────────────────┘
                        ▼
          Finding 去重 ──> SARIF 2.1.0 / findings.json ──> CI gate
```

### 1.1 为什么是两阶段而不是上下文敏感重分析

给每个形参灌唯一 marker 污点 `param:<qual>#<arg>` 后，函数的行为与调用者
无关：sink 是否可达、返回值依赖哪些形参、对 `self.x`/全局写了什么，全部
表现为 marker 集合（掩码）。因此每个函数只分析一次，调用点做一次
「marker → 真实污点」的字典替换即可。397 个模块、1.38 万个函数的全量扫描
约 13 秒，增量（仅缓存命中）约 6 秒。

## 2. CFG（`taint_sa/cfg.py`）

基本块 = 直线语句序列，块间显式边：

- `if/elif/else`：true/false 两条边 + 合流块，污点做 may-merge（任一支带毒
  则合流带毒）
- `while`/`for`：循环回边 + 退出块，FIFO worklist 迭代到状态不动点
- `try/except`：try 体每个块都连向 handler（异常可在任意点抛出，保守连通）
- `return/raise/break/continue`：终结边
- 嵌套函数不内联，作为词法作用域单元，通过 `C:` 闭包槽与外层交换污点

## 3. 污点状态（`taint_sa/model.py`）

四类槽位，前缀隔离命名空间：

| 槽位 | 用途 | 例子 |
|---|---|---|
| `L:` | 局部变量/形参 | `L:cmd` |
| `S:` | 实例属性（无对象敏感性，may 合并） | `S:cmd` 对应 `self.cmd` |
| `C:` | 闭包单元 | `C:email` |
| `G:` | 模块全局（环境变量源落这里） | `G:APP_TARGET` |

`Taint` 带 `sources`、传播 `path`、`sanitized` 标记。**sanitizer 不灭掉 source
证据，只让污点失活**——失活污点再参与拼接不会复活，但报告里仍能看到原始来源。

对象类型单独用 `_TypeTag` 存在 `State.types`，让 `job.run()` 这种局部对象的
方法调用能解析回 `SyncJob.run` 的摘要。

## 4. Source / sink / 策略配置

### Source（语言事实，代码内识别）

- Flask：`request.args/form/json/values/cookies/headers` 的下标与 `.get`
- Celery：`@celery.task`（含带参/不带参装饰器）标记的函数，形参直接灌
  `celery.<arg>` 污点
- 环境变量：`os.getenv`、`os.environ[...]`、`os.environ.get`

### Sink（语言事实 + 配置化包装）

- 直接 sink：`subprocess.run/call/Popen/check_call/check_output`、
  `os.system`、`os.popen`
  - `shell=True` + 污点字符串 → `concat_shell`
  - argv 列表里出现 `["/bin/sh","-c", x]` 且 x 带毒 → `arglist_misuse`
  - argv[0]（程序名）带毒 → `arglist_misuse`
- 配置化（`config/sanitizers.json`，可增删）：
  - `shell_wrappers`：首参按 shell 字符串判定
  - `safe_wrappers`（`shell=False`）：永不告警
  - `template_renderers`：任一渲染入参带毒则渲染结果带毒
  - `sanitizers`：返回值灭活

### 关键判定：常量与净化的良性场景不报

- 纯字面量命令/argv（`"df -h"`、`["/usr/bin/uptime"]`）：`Value.literal` 为真
- 常量 dict 白名单下标（`ALLOWED_SERVICES[name]`）：下标结果是字典里的常量值
- `shlex.quote` / `basename` / `int` / `allow_enum`：灭活或返回非字符串类型
- 未配置为 sanitizer 的未知函数：**污点保守透传**，不享受净化待遇

## 5. 跨过程传播与锚点归属

`sync_run()` 里 `job = SyncJob(request.form["source"]); job.run()` 的链路：

1. `SyncJob.__init__` 摘要记录 `self_writes.cmd = {marker#source}`
2. 构造调用把实参真实污点写进当前帧 `S:cmd`，并把 `job` 的类型记为 `SyncJob`
3. `job.run()` 经类型标签解析到 `SyncJob.run`；其摘要 sink 掩码
   `marker#self:cmd` 由当前帧 `S:cmd` 的真实污点实例化
4. 报在 **callee 内实际执行行 31**（`shellwrap.run_shell(self.cmd)`），
   而不是调用行 36——label 口径要求锚点是「污点实际到达的执行调用行」；
   只有 `lib/*` 共用包装的实现行被排除时才退回调用点行号

## 6. 增量一致性（`cli.py incremental`）

缓存 key = `sha256(模块内容哈希 + 直接 import 依赖哈希)`，再做依赖闭包扩散：
任一依赖变更，依赖方缓存失效。未失效模块直接反序列化摘要（摘要与调用上下文
无关），失效模块重分析。入口函数始终重放 CFG（其 CFG 很小），保证全量/增量
同口径。`--verify` 会在增量后再跑一遍全量并比对 finding 身份集合，不一致
直接退出码 3。

## 7. 跨过程传播在什么条件下必须主动截断

静态分析的终止性要求在以下四类条件下**必须主动截断**，否则分析不终止或
成本失控：

1. **递归环（直接/间接自调用）**：A→B→A 的调用环会让摘要实例化无限展开。
   命中 `_active` 集合里的函数时，返回保守空摘要占位并记录 `truncated`。
2. **调用深度超过上限**（默认 40 层）：防止装饰器/包装器层层嵌套导致的
   路径爆炸，`max_call_depth` 兜底。
3. **CFG 不动点迭代超预算**：`max_iterations × 块数` 仍未收敛时截断循环
   状态（当前语料 0 次触发）。
4. **外部不可解析目标**：仓库外、动态分派（`getattr(obj, name)`）、
   反射/`eval`/`exec` 拼出的调用目标：不做臆测，按未知函数处理——参数污点
   保守透传，但不虚构 callee 摘要。

### 截断后怎么保证不丢关键路径

核心思路是**截断只发生在摘要实例化层，不切断污点流本身**，配合四层补偿：

1. **marker 掩码与真实污点解耦**：递归环上返回的空摘要只影响「这一层的
   返回值掩码」，调用点实参的真实污点仍然存在于调用者帧的槽位里；环上
   任何一个函数体内的直接 sink（`subprocess`/`os.system`）在阶段 1 建摘要
   时就已经用 marker 记录，不受环截断影响。
2. **未知函数污点透传**：外部函数不截断污点，只丢失「callee 内部结构」。
   若透传后的污点随后到达本帧可见 sink，照常告警——本语料 50 条链路没有
   一条依赖被截断的外部 callee 内部行为。
3. **源点内建识别，不依赖跨过程可达性**：Flask/Celery/env 三类 source 在
   表达式层直接识别，不需要从框架入口一路跟踪到 handler，因此入口侧的
   调用链被截断不会让 source 消失。
4. **截断可观测、可回归**：所有截断事件写入 `inter.truncated`，
   `scan --show-truncation` 可打印；CI 测试固定当前语料截断数为 0，
   一旦新代码引入递归/超深调用导致截断，测试先红，避免静默漏报。

这套策略的取舍是：宁可在截断点保留 may-污点（可能带来少量噪声），也不
清空状态（必然漏报）；而 sanitizer 灭活、常量字面量、白名单下标这些高精度
去噪手段不受截断影响，实测 50 条样本召回 100%、误报 0。

## 8. 性能实测（本机，397 模块 / 197,523 行）

| 模式 | 耗时 | 结果 |
|---|---|---|
| 全量 | ~13–16 s（预算 <180 s） | 50 findings，召回 100%，FPR 0% |
| 增量（0 变更，全缓存命中） | ~6–10 s（预算 <15 s） | 与全量 finding 集合完全一致 |
| 增量（1 文件变更） | ~6 s | 50 findings，一致性自检通过 |

## 9. 入口

```bash
python -I analyze.py scan        --root . --config config/sanitizers.json \
                                 --sarif out.sarif --json out.json --cache .cache.json
python -I analyze.py incremental --root . --config config/sanitizers.json \
                                 --cache .cache.json --sarif inc.sarif [--verify]
python -I analyze.py gate        --baseline .ci/baseline.sarif --sarif inc.sarif
```
