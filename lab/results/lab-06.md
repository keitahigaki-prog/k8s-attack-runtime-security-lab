## Lab 06: ファイルレス実行（メモリ上での実行）

- MITRE ATT&CK for Containers: T1059.004 (Unix Shell), T1620 (Reflective Code Loading)
- 前提: `os.memfd_create`でディスクに書き込まず、メモリ上に展開したバイナリをexecする

### 試行錯誤：シェバンスクリプトでは「ファイルレス」にならない

最初に試した実装は、memfdに`#!/bin/sh`で始まるシェルスクリプトを書き込み、`os.execv("/proc/self/fd/<fd>", ...)`で実行するものだった。これは実行自体は成功する（`echo`や`id`も動く）が、**Falcoの`proc.exepath`は「ディスク上の実体（`/bin/busybox`）」を指しており、`memfd:`にはならなかった**。

理由：シェバン行のあるスクリプトをexecすると、カーネルの`binfmt_script`機構が「本当のインタプリタ」（`/bin/sh`→実体は`/bin/busybox`）を**改めてディスクから**ロードする。memfd上のスクリプトは単なる「どのインタプリタに何を食わせるか」の指示書に過ぎず、**実際に実行される機械語はディスク上のbusyboxバイナリ**。これでは「ファイルレス実行」の体をなしていない。

### 修正：ELFバイナリ自体をmemfdに展開

本当にファイルレスにするには、**シェバンスクリプトではなく実行可能なELFバイナイトそのもの**をmemfdに書き込む必要がある：

```python
import os
with open("/bin/busybox", "rb") as f:
    data = f.read()
fd = os.memfd_create("payload")
os.set_inheritable(fd, True)
os.write(fd, data)
os.execv("/proc/self/fd/%d" % fd, ["busybox", "sh", "-c", "echo FILELESS_EXEC_OK; id"])
```

（`/bin/busybox`の実体を読み出し、そのバイト列をそのままmemfdに書いてexec。busyboxはmulti-callバイナリなので、argvの与え方でシェルとして振る舞わせる。）

### 結果：攻撃は成立、かつ正しく検知

```
FILELESS_EXEC_OK
uid=0(root) gid=0(root) ...
```

Falcoの検知結果（実測）：

```
11:22:35.118244069: Critical Fileless execution via memfd_create |
  process=3 proc_exepath=memfd:payload command=3 sh -c echo FILELESS_EXEC_OK; id
  exe_flags=EXE_WRITABLE|EXE_FROM_MEMFD container_name=app
  pod=vulnerable-webapp-... ns=lab
```

`proc_exepath=memfd:payload`で正しく「ディスク実体を持たない」ことが示されている。さらに、Falcoの内部フラグに**専用の`EXE_FROM_MEMFD`フラグが用意されている**ことも実機で確認できた——`exe_flags`を直接見る方がmemfdパス文字列のパターンマッチより頑健な可能性があり、カスタムルールの改善余地として記録しておく。

### 考察（本文修正用）

- 本文で単純に「シェバンスクリプトをmemfdに置けばファイルレス実行になる」と書いていた箇所は**技術的に不正確**。シェバン経由は「インタプリタの指示書をメモリに置いただけ」で、実行される機械語自体はディスク上にある。真にファイルレスなのは、**ELFバイナリそのものをmemfdに展開してexecする**ケースのみ。
- カスタムルールの条件は`proc.exepath`の文字列マッチで機能したが、より本質的には`exe_flags`の`EXE_FROM_MEMFD`フラグを見る方が実装として筋が良い可能性がある（今後の改善候補）。
