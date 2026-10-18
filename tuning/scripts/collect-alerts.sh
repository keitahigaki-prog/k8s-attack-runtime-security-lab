#!/usr/bin/env bash
# Falco の JSON アラートを集め、ルール × namespace × イメージで件数を集計する。
#   ./collect-alerts.sh [since]   例: ./collect-alerts.sh 15m
#
# 注意: Docker Desktop 上の kind クラスタはすべて同じ Linux カーネルを共有するため、
# modern_ebpf の Falco は「他の kind クラスタのコンテナ」のイベントも拾う。
# ここでは tuning-lab ノード上の containerd が知っているコンテナ ID に絞って集計する。
set -euo pipefail
CTX="${CTX:-kind-tuning-lab}"
NODE="${NODE:-tuning-lab-control-plane}"
SINCE="${1:-15m}"
OUT="${OUT:-alerts.jsonl}"

IDS=$(docker exec "$NODE" crictl ps -a -q | cut -c1-12 | jq -R . | jq -sc .)

kubectl --context "$CTX" -n falco logs ds/falco -c falco --since="$SINCE" \
  | grep '^{' \
  | jq -c --argjson ids "$IDS" 'select(.output_fields["container.id"] as $c | ($ids | index($c)) != null or (.output_fields["k8s.ns.name"] // null) != null)' \
  > "$OUT" || true

echo "# alerts: $(wc -l < "$OUT" | tr -d ' ') ($OUT, since $SINCE, node $NODE)"
jq -r '[.rule, (.output_fields["k8s.ns.name"] // "-"), (.output_fields["container.image.repository"] // "-")] | @tsv' "$OUT" \
  | sort | uniq -c | sort -rn
