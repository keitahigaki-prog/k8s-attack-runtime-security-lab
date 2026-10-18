#!/usr/bin/env bash
# 正常業務ワークロード（N1〜N7）をひととおり動かし、ノイズを発生させる。
# 常駐系（N1, N3b, N6）は放っておいても周期的に動くが、測定の再現性のため明示的に一巡させる。
set -euo pipefail
CTX="${CTX:-kind-tuning-lab}"
K=(kubectl --context "$CTX")
TAG="${TAG:-$(date +%H%M%S)}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# CronJob 系（N2b, N4, N5）を手動で 1 回ずつ実行
for cj in apps/config-render ops/password-expiry-audit ops/secret-leak-check; do
  "${K[@]}" -n "${cj%/*}" create job "${cj#*/}-$TAG" --from=cronjob/"${cj#*/}" >/dev/null
done

# 常駐系を再起動して起動直後の挙動（N6 のログ切り詰め）も踏ませる
"${K[@]}" -n apps rollout restart deploy/legacy-app >/dev/null

# N7: SRE の調査セッション
"$HERE/sre-debug-session.sh" >/dev/null 2>&1 || true

for cj in apps/config-render ops/password-expiry-audit ops/secret-leak-check; do
  "${K[@]}" -n "${cj%/*}" wait --for=condition=complete job/"${cj#*/}-$TAG" --timeout=180s >/dev/null
done
"${K[@]}" -n apps rollout status deploy/legacy-app --timeout=180s >/dev/null
echo "noise run $TAG done"
