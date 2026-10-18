## Lab 01: 公開Webアプリ脆弱性経由の侵入

- MITRE ATT&CK for Containers: T1190 (Exploit Public-Facing Application)
- 前提: `vulnerable-webapp`（Python製、`/ping?host=`パラメータをシェルに直接渡すコマンドインジェクション脆弱性あり）を`lab` namespaceにデプロイ

### 手順

```bash
kubectl -n lab run attacker --rm -i --image=curlimages/curl --restart=Never -- \
  curl -s "http://vulnerable-webapp.lab.svc/ping?host=127.0.0.1;id"
```

### 結果：攻撃は成立

```
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: seq=0 ttl=64 time=0.052 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.052/0.052/0.052 ms
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

`id`コマンドが実行され、コンテナ内でroot権限を取得できることを確認。

### Falcoの検知結果（実測）

```
10:53:13.998459647: Notice Redirect stdout/stdin to network connection | gparent=python3 ggparent=containerd-shim
  process=ping proc_exepath=/bin/busybox parent=sh command=ping -c 1 127.0.0.1
  container_name=app container_image_repository=docker.io/library/python container_image_tag=3.12-alpine
  k8s_pod_name=vulnerable-webapp-... k8s_ns_name=lab
```

**重要な実証結果**: 標準ルール `Terminal shell in container` は**発火しなかった**。ルール定義を確認したところ、条件に`proc.tty != 0`（ターミナルが接続されていること）が含まれており、これは`kubectl exec -it`のような対話的侵入を想定したものだった。**Webアプリ脆弱性経由でプログラム的にシェルが起動するケース（TTYなし）は、この標準ルールの検知対象外**。

代わりに発火したのは`ping`のraw socket使用に起因する`Redirect stdout/stdin to network connection`ルールで、これはコマンドインジェクション自体の検知ではなく偶発的な副作用。`id`コマンドの実行自体に対する検知は一切なかった。

### 考察（本文修正用）

- 「標準ルールでシェル起動を検知できる」という当初の想定は誤りだった。TTYなしのプログラム的なシェル起動は標準ルールの盲点。
- 次の研究Aの集計では「Initial Access: 標準ルールで検知 0/1」に修正が必要。

### カスタムルールでの検知（修正版）

最初に書いたカスタムルール案は`proc.pname in (python3, ...)`で親プロセス名を直接指定するものだったが、**実機では`proc.pname`が`<NA>`（未解決）になり、条件が一切マッチしなかった**。原因は、Falcoの標準マクロ`container_entrypoint`の定義:

```
condition: (not proc.pname exists or proc.pname in (runc:[0:PARENT], ..., containerd-shim, ...))
```

`not proc.pname exists`、つまり**親プロセス情報が解決できないケース自体を「コンテナのエントリポイント相当」として扱う**設計になっていた。そこで、親プロセス名を直接指定するのではなく、この`container_entrypoint`マクロを再利用する形に修正:

```yaml
- rule: Shell Spawned Without TTY
  condition: >
    spawned_process and container and shell_procs
    and proc.tty=0 and container_entrypoint
  priority: CRITICAL
```

この修正版は実機で確認済み（`lab/rules/custom_rules.yaml`）。

```
11:03:09.557265408: Critical Shell spawned without a tty (user=root container=app process=sh
  command=sh -c ping -c 1 127.0.0.1;id pod=vulnerable-webapp-5d8b8bc699-vlsvn ns=lab)
```

### 副次的な発見：kindラボ特有の挙動

同じイベントが、**攻撃対象のPodが実際には乗っていない他の2ノードのFalcoにも（メタデータ未解決の状態で）ログされていた**。kindの各"ノード"は独立したVM/物理ホストではなく、Docker Desktopの単一Linuxカーネルを共有するコンテナであるため、**あるノードのFalcoが他ノードの生syscallまで観測してしまう**。`container_name`/`k8s_pod_name`等のメタデータは、実際にそのコンテナが起動しているノードのFalcoでしか正しく解決されない。本番の（物理/VMが分離された）マルチノードクラスタではこの漏れ聞こえは起きないため、**第3章のラボ構築に注記が必要**。
