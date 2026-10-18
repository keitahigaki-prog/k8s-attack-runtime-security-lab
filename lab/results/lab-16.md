## Lab 16: クラウドメタデータAPI経由のクレデンシャル窃取

- MITRE ATT&CK for Containers: T1552.005 (Cloud Instance Metadata API)
- 前提: `vulnerable-webapp`からクラウドのインスタンスメタデータAPI（`169.254.169.254`）への接続を試みる

### 環境上の重大な制約：ローカルkindラボには本物のメタデータAPIが無い

このラボはDocker Desktop上のkindクラスタであり、実際のAWS/GCPのVM上で動いているわけではない。そのため、**`169.254.169.254`への接続は実際にはタイムアウトする**（応答するメタデータサービスが存在しない）：

```python
s.connect(('169.254.169.254', 80))  # → timed out
```

本Labで実証できるのは「**攻撃者がこのIPへの接続を試みたという事実をFalcoが検知できるか**」までであり、「実際にクラウドの一時認証情報が取得できるか」は検証対象外（検証するには実クラウドVM上のラボが必要）。この制約は本文に明記する。

### 重要な実証結果：標準ルールにメタデータAPI検知は存在しない

本文は「Falcoの標準ルールセットには、メタデータAPIの固定IPへの接続に反応するルールがクラウド向けに用意されている」と書いていたが、**実際には存在しなかった**。`grep -i "169.254.169.254\|metadata"`でヒットしたのは、GKEの`gke-metadata-server`という**許可イメージ名のリスト**（信頼済みコンポーネントとして除外する側の用途）のみで、検知用のルールは皆無だった。

### カスタムルールでの検知（実機確認済み）

```yaml
- rule: Contact Cloud Metadata Service From Container
  condition: >
    evt.type=connect and evt.dir=< and (fd.typechar=4 or fd.typechar=6)
    and fd.sip="169.254.169.254"
```

接続が（応答が無くても）**試みられた時点**で検知できた：

```
12:00:06.747912306: Critical Contact cloud metadata service from container
  (command=python3 connection=10.244.2.3:45604->169.254.169.254:80
  container=app pod=vulnerable-webapp-5d8b8bc699-vlsvn ns=lab)
```

`connect()`システムコールの発行自体を見ているため、相手が応答するかどうかに関わらず検知できる点は実務上重要（タイムアウトする試行も見逃さない）。

### 考察（本文修正用）

- 「標準ルールに用意されている」という記述を削除し、「標準ルールには存在せず、カスタムルールが必須」に訂正する。
- ローカルラボでの検証には実クラウド環境特有の制約があることを明記し、「このLabは接続試行の検知までの実証であり、認証情報の実取得は別途実クラウドでの検証が必要」と誠実に書く。
