## Lab 07: 特権コンテナ・hostPath悪用

- MITRE ATT&CK for Containers: T1611 (Escape to Host の前段)
- 前提: `misconfigured-pod`（`privileged: true` + hostPath `/`を`/host`にマウント）

### 手順

```bash
kubectl -n lab exec misconfigured-pod -- sh -c "chroot /host cat /etc/shadow | head -3"
```

### 結果：攻撃は成立

```
root:*:20591:0:99999:7:::
daemon:*:20591:0:99999:7:::
bin:*:20591:0:99999:7:::
```

### Falcoの検知結果（実測）

```
11:25:26.226259636: Critical Shell spawned without a tty (... command=sh -c chroot /host cat /etc/shadow | head -3 ...)
11:25:26.238881178: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow
  process=cat proc_exepath=/host/usr/bin/cat parent=sh command=cat /etc/shadow
```

### 重要な訂正：「chroot Executed in Privileged Container」ルールは実在しない

標準ルールセット（`falco_rules.yaml`）を`grep -i chroot`で検索したが、**chrootに言及するルールは1件も存在しなかった**。本文で書いた「`chroot`実行自体を検知する標準ルール」は架空の記述だった。

実際に検知できたのは：
1. 自前のカスタムルール`Shell Spawned Without TTY`（Lab1で修正したもの）がコマンド全体の実行を捉えた
2. 標準ルール`Sensitive file opened for reading by non-trusted program`（本文では「Read sensitive file untrusted」という名前で書いていたが、実際のルール名はこちら）が`/etc/shadow`への`openat`を正しく検知した。興味深いのは、**`chroot`後のパス（`/etc/shadow`）がホスト側の実ファイルであっても、Falcoはコンテナのマウント名前空間をまたいで正しくファイルパスを解決し検知できた**点。

### 考察（本文修正用）

- ルール名を実際のもの（`Sensitive file opened for reading by non-trusted program`）に訂正し、「chroot専用ルールは存在しない」ことを明記する。
- 「特権コンテナ+hostPathは検知よりAdmission Controllerでの予防が優先」という本文の結論自体は実機結果でも支持される（chroot専用の検知層が無いことがその裏付けになる）。
