## Lab 13: クラスタ内ネットワークスキャン

- MITRE ATT&CK for Containers: T1046 (Network Service Discovery)
- 前提: `vulnerable-webapp`から、worker2上の複数Podに対してポートスキャンを実行

### 環境上の注記：CNIはkindnet（Calicoではない）

第3章で「CNI flow log」の例としてCalicoを挙げていたが、**本ラボのkindクラスタは既定のkindnet CNIを使用しており、Calicoは導入していない**。flow log機能を使うにはCalico等への切り替えが必要で、今回の実機検証では見送り、本文がもう一つの選択肢として挙げていた`tcpdump`側のみ実証可能な構成だった。この点は第3章に注記として追加する。

### 手順

busybox shの`/dev/tcp`は使えなかった（bash専用構文のため）ため、Python3でソケットスキャンを実装：

```python
import socket
targets = ['10.244.1.11','10.244.1.4','10.244.1.23','10.244.1.24']
ports = [22,80,443,4444,8080,8888]
for ip in targets:
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((ip, port)); print(f'{ip}:{port} open')
        except Exception: pass
```

### 結果：攻撃は成立

```
10.244.1.11:4444 open
10.244.1.4:4444 open
10.244.1.24:8888 open
```

攻撃者リスナー（Lab5）・C2サーバ（Lab2）・デバッグサービス（Lab14用）の3つの「背後のサービス」を正しく発見できた。

### Falcoの検知結果（実測）：標準ルールは一切発火せず

**本文で言及した「Multiple Outbound Connections」ルールは標準ルールセットに存在しなかった**（`grep -i "outbound\|connection\|scan"`でヒットしたのは`Redirect STDOUT/STDIN to Network Connection in Container`と`Disallowed SSH Connection Non Standard Port`のみ、どちらも無関係）。実際、今回のスキャン（24回の接続試行、うち成功3回）に対しては**何も検知されなかった**。

### 考察（本文修正用）

- 「標準ルールの中には、短時間に大量の送信接続を行うプロセスに反応するものがある」という本文の記述は**誤り**。Falcoの標準ルールセットには接続回数・頻度ベースの汎用スキャン検知ルールは存在しない。
- これはむしろ**本文の核心的な主張（「syscallベースの検知とネットワークベースの検知は相互補完が必要」）を一段と強く裏付ける結果**になった——Falco単体では「検知の粒度が粗い」のではなく**「そもそも検知ロジックが無い」**。CNI flow log（今回は未検証）かtcpdumpによる観測が実質的に必須という結論に書き換える。
