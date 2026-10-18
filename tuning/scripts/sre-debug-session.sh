#!/usr/bin/env bash
# N7: SRE の調査セッションを再現する。
# kubectl exec -it で netshoot に入り、tcpdump でパケットを数個取って抜ける。
# 非対話環境でも TTY を割り当てるため script(1) を挟む。
set -euo pipefail
CTX="${CTX:-kind-tuning-lab}"
POD=$(kubectl --context "$CTX" -n ops get pod -l app=netshoot -o jsonpath='{.items[0].metadata.name}')

if [[ "$(uname)" == "Darwin" ]]; then
  script -q /dev/null kubectl --context "$CTX" -n ops exec -it "$POD" -- \
    bash -c 'tcpdump -i any -c 5 -nn port 53 >/dev/null 2>&1 & sleep 1; nslookup kubernetes.default >/dev/null; wait; exit'
else
  script -qc "kubectl --context $CTX -n ops exec -it $POD -- bash -c 'tcpdump -i any -c 5 -nn port 53 >/dev/null 2>&1 & sleep 1; nslookup kubernetes.default >/dev/null; wait; exit'" /dev/null
fi
