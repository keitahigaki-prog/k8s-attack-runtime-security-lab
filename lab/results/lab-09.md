## Lab 09: Linux Capabilities悪用（SYS_PTRACE）

- MITRE ATT&CK for Containers: T1611
- 前提: `cap-abuse-pod`（`CAP_SYS_PTRACE`を追加）

### 手順

```bash
kubectl -n lab exec cap-abuse-pod -- sh -c \
  "apk add --no-cache strace; strace -p 1 -f -e trace=none"
```

### 結果：攻撃は成立

`strace -p 1`でコンテナのPID 1（`sleep 3600`）にアタッチできた（`Process 1 attached`）。

### Falcoの検知結果（実測・本文より充実）

本文では「Capabilityが付与された**構成時点**で検知するのが効果的」と書いたが、実際にはFalcoは構成時点（Admission相当）ではなく実行時のsyscallしか見られない。その代わり、**実行時のptrace syscall自体を直接検知する標準ルールが複数存在し、どれも正しく発火した**：

```
Critical Executing binary not part of base image | proc_exe=strace exe_flags=EXE_WRITABLE|EXE_UPPER_LAYER
Warning  Detected ptrace PTRACE_ATTACH attempt | process=strace command=strace -p 1 -f -e trace=none
Notice   Detected potential PTRACE_TRACEME anti-debug attempt | process=strace
```

- `Executing binary not part of base image`：`apk add`でインストールしたstraceが、イメージの元レイヤーに存在しないバイナリ（`EXE_UPPER_LAYER`）として検知された。これは「イメージビルド後に追加されたツール」を汎用的に検知する強力なルールで、本文では触れていなかった。
- `Detected ptrace PTRACE_ATTACH attempt`：ptrace syscallそのものをピンポイントで検知。CAP_SYS_PTRACEの「付与」ではなく「実際の悪用」を捉えている。

### 考察（本文修正用）

- 「Capability付与時点の検知が効果的」という本文の結論は、**Falcoの実行時監視という性質上そもそも成立しない**（Falcoはsyscallしか見ない。付与時点の検知はAdmission Controller/OPA等の役割）。正しくは「**Falcoは`CAP_SYS_PTRACE`の"付与"ではなく"実際の悪用"(ptrace syscall)を直接検知できる**」に訂正する。
- 副産物として、`Executing binary not part of base image`という汎用的に強力なルールの存在を本文に追加する価値がある（Lab 7以降で繰り返し使えそうな観点）。
