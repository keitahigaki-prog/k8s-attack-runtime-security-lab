## Lab 10: 既知のエスケープ手法の再現（ホストバイナリ書き換え）

- MITRE ATT&CK for Containers: T1611 (Escape to Host)
- 前提: 実際のCVE（CVE-2019-5736等）の再現は、脆弱な旧バージョンrunc等の特別な環境構築が必要で実機検証の範囲を超えるため、**「エスケープが成功した結果として何が起きるか」＝ホストバイナリの書き換え**を、Lab 7の特権コンテナ（hostPath `/`マウント）から`chroot`して再現した

### 手順

```bash
kubectl -n lab exec misconfigured-pod -- sh -c \
  "chroot /host sh -c 'cp /usr/bin/true /tmp/true.bak && echo overwritten-by-lab10 >> /usr/bin/true && cp /tmp/true.bak /usr/bin/true'"
```

### 結果：攻撃は成立

ホスト側の`/usr/bin/true`に対する書き込みが成功した（実害を避けるためすぐ元に戻す処理を含む）。

### 重要な実証結果：「Write below binary dir」ルールは実在しない

本文で書いた標準ルール名を`falco_rules.yaml`全体から検索したが、**rule名に"binary dir"を含むものは1件も存在しなかった**。さらに`write`を含むrule名も、本Lab関連では`Netcat Remote Code Execution in Container`と`Drop and execute new binary in container`のみで、**「ホストのバイナリが書き換えられたこと」自体を検知する標準ルールは存在しない**ことを確認。これはFalco標準ルールセットの**実在するカバレッジの穴**。

### カスタムルールの試行錯誤

1本目の実装：`fd.name startswith "/host/usr/bin"`（hostPathマウント経由のパスを想定）→ **発火せず**。
原因：`chroot /host`した時点でプロセスの見る絶対パスが`/usr/bin/true`に変わり、`/host`プレフィックスは付かない。

2本目の実装（修正版・実機確認済み）：

```yaml
- rule: Write to System Binary Directory
  condition: >
    open_write and container
    and (fd.name startswith /usr/bin or fd.name startswith /usr/sbin
         or fd.name startswith /bin or fd.name startswith /sbin)
```

```
11:33:59.904768610: Critical Write to system binary directory (file=/usr/bin/true
  command=sh -c cp /usr/bin/true /tmp/true.bak && echo overwritten... command=... pod=misconfigured-pod ns=lab)
```

### 考察（本文修正用）

- 「Write below binary dir」という標準ルール名の記述を削除し、**「このカテゴリの検知は標準ルールセットに存在しない」**ことを明記する。
- カスタムルールを書く際の典型的な落とし穴として、「`chroot`後はパスの見え方が変わる」という点を追加する（Lab 2のプライベートIP除外と並ぶ、"素朴な実装が通用しない"実例として使える）。
