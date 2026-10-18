# k8s-attack-runtime-security-lab

[「攻撃して学ぶ Kubernetes Runtime Security」](https://zenn.dev/)の実験ラボ一式。Zenn本`zenn-falco-series`の[k8s-attack-runtime-security](https://github.com/keitahigaki-prog/zenn-falco-series/tree/main/books/k8s-attack-runtime-security)と対になるコード・ルール・実測ログのリポジトリです。

本書は、MITRE ATT&CK for Containersの8フェーズに沿って20本の攻撃シナリオ（Lab 1〜20）をkind上で実際に再現し、Falco（modern eBPF）・Kubernetes Audit Logsでどこまで検知できるかを検証します。**本文中の検知結果・ルール名は、すべてこのリポジトリで実行した結果に基づいています**（本文執筆時点の想定とは異なる結果になったケースも、その経緯ごと本文に記載しています）。

> **注記**: このリポジトリのトップレベルには`tuning/`というディレクトリもありますが、これは別の書籍（Falcoルールチューニングガイド）のための、別セッションによる作業内容です。本READMEおよび以下の内容は`kind/`・`lab/`のみを対象にしています。

## ディレクトリ構成

```
.
├── kind/
│   ├── kind-config.yaml       # 1 control-plane + 2 worker のkindクラスタ定義
│   └── audit-policy.yaml      # Kubernetes Audit Logsのポリシー
├── lab/
│   ├── manifests/              # 各Labで使う脆弱なワークロードのYAML（連番は対応するLab番号）
│   ├── rules/
│   │   └── custom_rules.yaml   # 本書で追加した全カスタムルール（試行錯誤の最終版）
│   └── results/
│       ├── lab-01.md 〜 lab-21-performance.md   # 各Labの実行手順・実測ログ・考察
│       └── research-a-summary.md                 # 全Lab横断の検知カバレッジ集計
└── README.md
```

## 前提

- Docker Desktop（または同等のcontainerdランタイム）
- [kind](https://kind.sigs.k8s.io/)
- kubectl
- helm

## クラスタの構築

```bash
mkdir -p kind/audit-logs
kind create cluster --config kind/kind-config.yaml
kubectl wait --for=condition=Ready nodes --all --timeout=120s
```

control-planeノードのkube-apiserverは、`kind/audit-policy.yaml`をマウントしてAudit Loggingが有効化された状態で起動します（`kind/audit-logs/audit.log`に出力。このディレクトリは`.gitignore`済みで、実行環境固有のログはコミットされません）。

## Falcoの導入

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true \
  --set-file customRules."rules-lab\.yaml"=lab/rules/custom_rules.yaml
```

`lab/rules/custom_rules.yaml`には、本書のLab 1・2・6・10・11・12・16で作成したカスタムルールの**最終版**が入っています。最初の実装がなぜ失敗したか（`proc.tty`依存、`outbound`マクロの私設IP除外、chroot後のパス変化、Falco自身のノイズ混入 等）は、対応する`lab/results/lab-XX.md`に経緯ごと記録しています。

## 脆弱なワークロードのデプロイ

```bash
kubectl apply -f lab/manifests/00-namespace.yaml
kubectl apply -f lab/manifests/01-vulnerable-webapp.yaml   # Lab 1, 5, 6, 13, 16, 17, 18-20
kubectl apply -f lab/manifests/02-c2-and-backdoor.yaml     # Lab 2
kubectl apply -f lab/manifests/04-deploy-bot.yaml          # Lab 4, 8, 15
kubectl apply -f lab/manifests/05-attacker-listener.yaml   # Lab 5
kubectl apply -f lab/manifests/07-misconfigured-pod.yaml   # Lab 7, 9, 10, 12
kubectl apply -f lab/manifests/11-hostpid-pod.yaml         # Lab 11
kubectl apply -f lab/manifests/14-debug-service.yaml       # Lab 13, 14
```

`lab/manifests/21-load-generator.yaml`（研究C・負荷試験用）は、**必ずCPU上限（`resources.limits.cpu`）付きの版を使ってください**。本書の執筆中、CPU上限無しの版を実行してDocker Desktop VM全体が6分以上無応答になるインシデントが実際に発生しています（詳細は`lab/results/lab-21-performance.md`）。

## 各Labの実行手順

個別の攻撃コマンド・期待される（そして実際に得られた）Falco/Audit Logsの出力は、`lab/results/lab-XX.md`に1本ずつ記載しています。まず`research-a-summary.md`で全体像をつかんでから、気になるLabの詳細に進むのがおすすめです。

| Lab | フェーズ | 本書の章 |
|---|---|---|
| 1-4 | Initial Access | 第4章 |
| 5-6 | Execution | 第5章 |
| 7-9 | Privilege Escalation | 第6章 |
| 10-12 | Container Escape | 第7章 |
| 13-15 | Lateral Movement | 第8章 |
| 16-17 | Credential Access / Exfiltration | 第9章 |
| 18-20 | 攻撃チェーンの相関再構築（研究B） | 第10章 |
| 21 | イベント負荷・リソース評価（研究C） | 第11章 |

## 後片付け

```bash
kind delete cluster --name attack-lab
```

## ライセンス

実験コードの内容は個人の見解であり、所属組織の公式見解ではありません。
