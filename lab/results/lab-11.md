## Lab 11: 共有Namespace/Volumeの悪用（hostPID）

- MITRE ATT&CK for Containers: T1611
- 前提: `host-pid-pod`（`hostPID: true`のみ、Capabilitiesは追加なし）

### 重要な実証結果：hostPIDだけでは他プロセスのenvironを読めない

本文は「hostPID: trueで他プロセスの環境変数に直接アクセスできる」と説明していたが、実機では**`CAP_SYS_PTRACE`を持たない通常のコンテナは`Permission denied`で弾かれた**：

```bash
kubectl -n lab exec host-pid-pod -- sh -c "cat /proc/245/environ"
# cat: can't open '/proc/245/environ': Permission denied
```

`ps aux`で他ノードの全プロセス（kubelet, containerd, systemd等）が**見える**ことは本文の記述どおりだが、`/proc/<pid>/environ`のような機微なファイルへの実際のアクセスには、カーネルの`ptrace_may_access`チェックが働き、**`hostPID`単体ではなく追加で`CAP_SYS_PTRACE`（Lab 9の権限）が必要**だった。

### 修正した前提で再実行：`hostPID` + `CAP_SYS_PTRACE`

```bash
kubectl -n lab exec host-pid-ptrace-pod -- sh -c "cat /proc/245/environ | tr '\0' '\n' | head -3"
```

```
HTTPS_PROXY=
HTTP_PROXY=
LANG=C.UTF-8
```

### Falcoの検知結果（実測、カスタムルールの大きな試行錯誤あり）

本文の「Read Environ of Other Process」ルールも標準ルールセットには存在しない（確認済み）。カスタムルール追加の過程で**実運用上重要なノイズ問題**に遭遇した：

最初の実装（`fd.name`に`/proc/`と`/environ`を含むかのみで判定）は、**1分間に約1000件のアラートを誤発火**させた。原因は、**Falco自身が`/host/proc`経由で全ホストプロセスのenvironを定期的に読み取っている**（プロセス情報のエンリッチメントのため）ことで、これが"container"条件にも合致してしまっていた。

修正（実機確認済み）：

```yaml
condition: >
  open_read and container
  and fd.name contains "/proc/" and fd.name contains "/environ"
  and not fd.name contains "self"
  and not fd.name startswith "/host/proc"
  and proc.name != falco
```

修正後は、ノイズがゼロになり、実際の攻撃だけが検知された：

```
11:45:59.062080566: Warning Read /proc/<pid>/environ (file=/proc/245/environ
  command=cat /proc/245/environ container=app pod=host-pid-ptrace-pod ns=lab)
```

### 考察（本文修正用）

- 「hostPIDだけで他プロセスの機微ファイルを読める」という本文の前提は不正確。**実際には`hostPID`（可視性）＋`CAP_SYS_PTRACE`（アクセス権）の組み合わせが必要**という、より正確な記述に修正する。
- カスタムルール開発における「Falco自身の動作が検知対象と見分けがつかなくなる」という、本書で初めて遭遇したタイプのノイズ問題を追加の学びとして記録する。
