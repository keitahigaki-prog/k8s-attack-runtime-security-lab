## Lab 03: Kubelet誤公開APIの悪用

- MITRE ATT&CK for Containers: T1552.007 (Container API)
- 前提: 本文では「kubeletの読み取り専用ポート（10255）が誤って外部に公開された状態」を想定していた

### 実機確認

```bash
# worker nodeコンテナ内から直接確認
docker exec attack-lab-worker cat /var/lib/kubelet/config.yaml | grep -A3 "^authentication:\|^authorization:"
docker exec attack-lab-worker curl -s -m 3 http://localhost:10255/pods; echo RC=$?
docker exec attack-lab-worker curl -sk -m 3 https://localhost:10250/pods
```

### 結果：本文の前提が現在のKubernetesには当てはまらない

```
authentication:
  anonymous:
    enabled: false
authorization:
  mode: Webhook

--- 10255 ---
RC=7   # Connection refused — ポート自体がlistenしていない

--- 10250 (anonymous) ---
Unauthorized
```

- **読み取り専用ポート10255は、そもそもlistenしていなかった**（kubeletのデフォルトが変わり、この古いHTTPポートは実質廃止されている）。本文がLab 3の元ネタとして挙げたTesla事例（2018年）・Kinsingキャンペーン（2020年〜）は、**当時のkubeletのデフォルト設定（`--anonymous-auth=true`がデフォルトだった時代）**を前提にしたものであり、現在のkubeadm/kind/マネージドKubernetesのデフォルトではこの経路はすでに塞がれている。
- セキュアポート（10250, HTTPS）は生きているが、`authentication.anonymous.enabled: false` + `authorization.mode: Webhook`により、匿名リクエストは`Unauthorized`で弾かれる。
- クラスタ内に`system:anonymous`や`system:unauthenticated`グループへの過剰な`ClusterRoleBinding`も存在しないことを確認済み（`system:public-info-viewer`のみ）。

### 考察（本文修正用）

この結果は**ネガティブな結果そのものが本の価値**になる。「2018〜2020年当時は深刻な脅威だったが、現在のKubernetesデフォルトは既にこの経路を塞いでいる」という、**セキュリティの時間的変化を示す実証データ**として書き直す。

Lab 3を成立させるには、意図的に`--anonymous-auth=true`等の非推奨設定を復元する必要があり、それ自体が「なぜこの設定変更が危険なのか」を示す追加の学習ポイントになる（本文ではこの意図的な再現は行わず、デフォルトの安全性を確認したことを明示するに留める）。

研究Aの集計では、Lab 3は「観測できない」ではなく「**現在のデフォルト設定では、そもそも攻撃が成立しない**」に分類を変更する。
