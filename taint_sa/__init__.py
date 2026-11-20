"""taint_sa —— 只基于标准库 ``ast`` 的 Python 命令注入静态分析器。

模块划分
========
- :mod:`taint_sa.model`      污点状态 / 槽位 / finding 数据结构
- :mod:`taint_sa.config`     可配置白名单（sanitizer / wrapper / renderer）
- :mod:`taint_sa.impres`     import 解析：语法名 -> 仓库内全限定模块名
- :mod:`taint_sa.cfg`        自建控制流图（语句块 + 分支边）
- :mod:`taint_sa.expr`       表达式求值：污点传播与常量字面量判定
- :mod:`taint_sa.inter`      过程内/跨过程污点分析（worklist 不动点）
- :mod:`taint_sa.sarif`      SARIF 2.1.0 输出
- :mod:`taint_sa.cli`        全量 / 增量 / CI 门禁入口

不依赖任何第三方规则引擎；唯一的「语法解析库」是标准库 ``ast``。
"""

RULE_ID = "command_injection"
