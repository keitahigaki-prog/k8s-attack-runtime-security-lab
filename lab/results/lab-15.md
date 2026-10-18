## Lab 15: ノード間移動（盗んだトークンでのexec悪用）

- MITRE ATT&CK for Containers: T1021.004, T1550
- 前提: Lab 4で発行した`deploy-bot`のトークンに、`pods/exec`権限を追加（過剰権限なCIトークンという想定を維持するための調整）

### 前提の訂正：最初はpods/exec権限が無く失敗

Lab 4の`deploy-bot`は元々`secrets`のget/listのみで、`pods/exec`権限が無かった。最初の試行は403 Forbiddenで失敗し、これ自体が「最小権限で運用していれば、この横展開は最初から成立しない」という実証結果になった。本Labの前提を満たすため、ClusterRoleに`pods/exec`を追加した。

### 手順

```bash
TOKEN=$(kubectl create token deploy-bot -n lab --duration=1h)
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl --server="$APISERVER" --token="$TOKEN" --insecure-skip-tls-verify=true \
  -n lab exec debug-service-76dcf69b7b-d87hq -c app -- id
```

### 結果：攻撃は成立（ノードをまたいだexec）

```
uid=0(root) gid=0(root) groups=...
```

`over-privileged-sa-pod`（worker上）で盗んだトークンを使い、**別ノード（worker2）上のPod**に対してexecできた。

### Audit Logsの記録（実測・本文の想定と一致）

```json
{"verb": "create", "user": {"username": "system:serviceaccount:lab:deploy-bot", ...},
 "objectRef": {"resource": "pods", "namespace": "lab", "name": "debug-service-...", "subresource": "exec"},
 "sourceIPs": ["172.19.0.1"]}
```

このLabは**本文の想定どおりの結果**になった。`pods/exec`というsubresourceへの`create`リクエストとして、誰が・どのPodに対してexecしたかが正確に記録されている。

### Falcoの検知結果：execされた中身は見えるが「execされたこと」自体は分からない

`id`コマンドの実行自体はFalco側でも観測できる（通常のプロセス実行イベントとして）が、**それが「正規のkubectl execで入ったのか」「攻撃者が盗んだトークンでexecしたのか」を区別する情報はFalco側には無い**。この区別には、Audit LogsのsourceIPsとuser情報との突合が必須——これは本文の結論をそのまま裏付ける。

### 考察（本文修正用）

- 本文の結論（「ノード間移動はAudit Logsが主役」）は実機でも支持される、数少ない「訂正不要」なLabだった。
- 追加の学び：**最小権限運用（pods/execを与えない）そのものが、このLabの攻撃を根本から防ぐ**という点を、本文に一言加える価値がある。
