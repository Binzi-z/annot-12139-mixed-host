#!/usr/bin/env python3
"""仓库根入口：供 ``python -I analyze.py ...`` 调用（-I 隔离模式下 PYTHONPATH
不生效，故在脚本内把仓库根加入 sys.path 后再导入包）。"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from taint_sa.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
