# override / condition 実測メモ（第3章・第8章用）

検証環境: tuning-lab（kind単ノード）、Falco 0.45.0（chart 9.2.0）、modern_ebpf。
検証用ルールは `/tmp/override-test*.yaml` に書き捨てで作り、本番の `rules/tuning-rules.yaml` とは分離して検証した（既存の exceptions と干渉させないため）。

## 1. override.condition: append は論理 AND

- ベース: `spawned_process and proc.name="canaryproc"`
- 追加（append）: `and proc.args contains "MUST_NOT_MATCH_V1"`（恒偽）→ **発火しない**
- 追加（append）を恒真の条件に差し替え: `and proc.name="canaryproc"`（恒真）→ **発火する**

結論: `override.condition: append` は `condition` の文字列をそのまま末尾に連結し、全体として `ベース条件 AND 追加条件` になる。恒偽な条件を足せば、ルール全体が無効化と同じ効果になる（ただし「ルールを消した」のではなく「踏めなくした」だけなので、disable より追跡しやすい）。

## 2. override.condition: replace はベースを完全に破棄

- ベース: `spawned_process and proc.name="neverused"`
- replace: `spawned_process and proc.name="canaryproc2"`
- `canaryproc2` を実行 → **発火した**（`neverused` 側は一度も満たされていないのに関係なく発火）

結論: `replace` はベースの条件文字列を完全に捨てて差し替える。upstream の意図（どんな事象を狙っていたか）を継承しないので、使うときは desc も合わせて書き換えないと「ルール名と実際の検知内容がズレる」事故になる。

## 3. override.priority: replace の実例

`Terminal shell in container` を `priority: INFORMATIONAL` + `override: {priority: replace}` で上書き。
実際に `kubectl exec -it` で netshoot に入ったところ、アラートは `Critical` ではなく `Informational` で記録された（2件とも）。
→ 「ルールは消さず、監査ログとして残すが優先度を下げる」という第6章の方針を priority override で実現できる。

## 4. override.exceptions: append を使うと素朴な上書きにならない

`tuning-rules.yaml` では N1/N2b/N4/N5/N7 の5箇所で `exceptions: [...]` + `override: {exceptions: append}` を使用。
これにより upstream 側の `exceptions:` フィールド（空のことが多い）を壊さずに追加できることを、ベースライン実測（15件→2件）で確認済み（`results/baseline-alerts.jsonl` → `results/tuned-alerts.jsonl`）。

## 5. 存在しないルール名への override はロード時にエラーで止まる（サイレント無視されない）

```yaml
- rule: This Rule Does Not Exist Anywhere
  condition: " and proc.name=\"x\""
  override:
    condition: append
```

→ `falco -V` で以下のエラーになり、**起動しない**:

```
LOAD_ERR_VALIDATE (Error validating rule/macro/list/exception objects):
Rule uses 'append' or 'override.<key>: append' but no rule by that name already exists
```

結論: ルール名のタイプミス（upstream側でルール名が変わった、など）は起動時に検出できる。CI での `falco -V` 実行を本番投入前に必ず挟むべき根拠になる（→ 第11章）。

## 6. ルールファイルのロード順

```
Loading rules from:
   /etc/falco/falco_rules.yaml          ← 常に最初
   /etc/falco/rules.d/override-test.yaml ← rules.d 配下はファイル名のアルファベット順
   /etc/falco/rules.d/tuning-rules.yaml
```

複数のカスタムファイルが同じルールを override している場合、**後からロードされたファイルの override が最終的に効く**（アルファベット順で後ろのファイルが勝つ）。チームでファイルを分けるときは、命名規則で優先順位を管理する必要がある。

## 7. namespace／ラベルをキーにした例外は、コンテナメタデータ解決の race で抜けることがある

N6（legacy-app のログ切り詰め）で `Clear Log Activities` に対して
`allowed_clear_log_files` マクロを `k8s.ns.name="apps" and k8s.pod.label[app]="legacy-app" and fd.name="/var/log/access.log"` で置き換えていたが、
Pod 再起動直後の短命プロセスで `k8s.ns.name` が `<NA>`（`container_name=host` 扱い）になるイベントが観測され、
マクロの条件が偽と評価されて **チューニング済みのはずのルールが発火した**。

```json
{"rule":"Clear Log Activities","output":"... file=/var/log/access.log ... container_id=host container_name=host ... k8s_ns_name=<NA> ..."}
```

これは攻撃本（k8s-attack-runtime-security-lab）の Lab 1 で見つかった「短命プロセスはコンテナ・K8sメタデータが解決される前に syscall を発行することがある」という知見と同種の現象。
→ 第6章で扱うべき教訓: **namespace/pod label キーの例外は、起動直後や短命プロセスでは効かないことがある**。`fd.name` のような、メタデータ解決に依存しないフィールドを主キーにし、namespace/label は「絞り込みの補助」程度に留めるほうが安全。
