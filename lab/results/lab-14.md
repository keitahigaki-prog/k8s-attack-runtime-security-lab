## Lab 14: 他Podへの侵入・Pod間移動

- MITRE ATT&CK for Containers: T1021
- 前提: Lab 13で発見した`debug-service`（認証なしでコマンドを実行できる模擬デバッグサービス、worker2上）に対して、`vulnerable-webapp`から接続する

### 手順

```python
import urllib.request
req = urllib.request.Request('http://10.244.1.24:8888/', data=b'id; hostname', method='POST')
print(urllib.request.urlopen(req, timeout=5).read().decode())
```

### 結果：攻撃は成立

```
uid=0(root) gid=0(root) groups=...
debug-service-76dcf69b7b-d87hq
```

着地点のPod名が返ってきており、Pod間移動が成立している。

### 重要な実証結果：Lab 1で作ったカスタムルールが、別のコンテナでは発火しなかった

最初の実行では**何の検知もされなかった**。原因を調べたところ、Lab 1で修正した`Shell Spawned Without TTY`ルール（`container_entrypoint`マクロに依存する実装）が、**`debug-service`コンテナでは`proc.pname`が`python3`として正しく解決されていた**ため、`container_entrypoint`（「親プロセス情報が無いか、ランタイムシムであること」を要求するマクロ）の条件を満たさず、ルール全体が不発火になっていた。

Lab 1のvulnerable-webappコンテナでは`proc.pname`が`<NA>`（未解決）だったため偶然`container_entrypoint`を満たしていたが、**これはFalcoのプロセスキャッシュの状態に依存する、再現性のない偶然の一致だった**ことが今回判明した。

### 修正：`container_entrypoint`条件を削除

```yaml
condition: >
  spawned_process and container and shell_procs and proc.tty=0
```

親プロセス名の解決状況に依存せず、TTYなしのシェル生成を一律で検知するように変更。実機で両方のコンテナ（vulnerable-webapp、debug-service）に対して正しく発火することを確認：

```
11:54:08.384519196: Critical Shell spawned without a tty (... container=app pod=debug-service-76dcf69b7b-d87hq ns=lab ...)
```

トレードオフとして、対話シェルを伴わない正当な自動化スクリプトも拾ってしまう可能性があり、再現率（recall）を上げる代わりに適合率（precision）が下がる。

### 考察（本文修正用）

- 第3〜7章で使ってきたカスタムルールの説明を、この修正版に差し替える必要がある。**「Falcoのプロセスキャッシュの解決状況は環境依存で、それに依存したルールは再現性がない」**という教訓は、研究A（検知カバレッジ）の章で一般化して扱う価値がある重要な論点。
