# CI 门禁脚本：全量扫描 -> 与基线比对 -> 新增违规红灯
# 用法（仓库根目录）：bash .ci/run_ci.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BASELINE=".ci/baseline.sarif"
CURRENT=".ci/current.sarif"
CACHE=".taint_cache.json"

echo "[ci] 增量扫描（无缓存时自动退化为全量）"
if [[ -f "$CACHE" ]]; then
  python -I analyze.py incremental --root . --config config/sanitizers.json \
      --cache "$CACHE" --sarif "$CURRENT"
else
  python -I analyze.py scan --root . --config config/sanitizers.json \
      --cache "$CACHE" --sarif "$CURRENT"
fi

echo "[ci] 门禁：只拦截合并前的新增违规"
python -I analyze.py gate --root . --baseline "$BASELINE" --sarif "$CURRENT"
