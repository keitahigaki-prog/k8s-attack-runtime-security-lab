## Lab 02: 誤設定・悪意あるイメージの実行

- MITRE ATT&CK for Containers: T1204.003 (Malicious Image)
- 前提: `backdoor-demo`（起動時にC2サーバへビーコン接続する模擬バックドア）を、クラスタ内に自前で立てた`c2-server`（ClusterIP固定: `10.96.99.99`）に対して実行。実際の外部マルウェア配布元には接続しない。

### 手順

```bash
kubectl apply -f lab/manifests/02-c2-and-backdoor.yaml
kubectl -n lab logs backdoor-demo
```

### 結果：ビーコンは成立

```
backdoor-demo: beaconing to C2...
c2-ack
```

### Falcoの検知結果（実測・標準ルールのみ）

標準ルールでは、`backdoor-demo`側（クライアント）の接続自体は検知されなかった。発火したのは`c2-server`側（nc -e echo を使うリスナー）の`Netcat runs inside container that allows remote code execution`のみで、これは本書が模した「ビーコン送信側の検知」とは別物だった。

### 重要な実証結果：標準の`outbound`マクロは私設IPアドレス空間を除外する

カスタムルール第一案は、Falco標準の`outbound`マクロの上に構築していた：

```yaml
condition: outbound and fd.sip in (known_malicious_ips)
```

これは**一切発火しなかった**。原因を`falco_rules.yaml`で確認したところ、`outbound`マクロの定義に、RFC1918プライベートアドレス空間（`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`）を除外する条件が組み込まれていた。Kubernetesのservice CIDR（本ラボでは`10.96.0.0/12`）は`10.0.0.0/8`に含まれるため、**C2サーバをクラスタ内のプライベートIPに置いた瞬間、標準の`outbound`マクロに依存するルールは原理的に検知できなくなる**。

これは「プライベートIP＝信頼できる内部通信」という標準マクロの前提が、**クラスタ内に設置されたC2リレーやクラスタ内横展開の着地点**には当てはまらないことを示す、実務上重要な発見。

### 修正版カスタムルール（検証済み）

`outbound`マクロを使わず、`evt.type=connect`を直接評価する形に変更：

```yaml
- rule: Outbound Connection to C2 Server
  condition: >
    evt.type=connect and evt.dir=< and (fd.typechar=4 or fd.typechar=6)
    and fd.sip in (known_malicious_ips)
  priority: CRITICAL
```

実機での検知ログ：

```
11:03:08.018784824: Critical Outbound connection to C2 server (command=nc
  connection=10.244.2.9:35551->10.96.99.99:4444 container=backdoor-agent
  pod=backdoor-demo ns=lab)
```

### 考察（本文修正用）

- 当初の本文は「標準ルールセットには該当ルールがないため、カスタムルールを追加した」という説明だったが、正確には**「カスタムルールの第一案も、標準マクロの隠れた前提（プライベートIP除外）によって機能しなかった」**という、もう一段深い教訓がある。
- 研究A（検知カバレッジ分析）に、「カスタムルールを書いても、既存マクロの暗黙の前提に引きずられて機能しないことがある」という論点を追加する価値がある。
