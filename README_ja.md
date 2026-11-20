<div align="center">
	<img width="150px" height="150px" alt="WAMB" src="https://raw.githubusercontent.com/CrossDarkrix/WAMB/master/WAMB.png">
</div>

[English](README.md) | 日本語

# WAMB — Win Anti Malware Blocker

ClamAV を主軸にした、Windows 向けの軽量マルウェア対策マネージャー (Go 製・単一 exe)。
常駐の Defender を置き換えるものではなく、その上に載せる「セカンドオピニオン」層です。

## 特徴

- **検出のみが既定** — 自動削除はしない。隔離は明示コマンドでのみ行う
- **clamd を使わない** — スキャンのたびに clamscan を起動する方式で、常駐メモリを食わない
- **ブラウザのクッキー / ログイン情報ストアは常時監視** — 除外指定でも外せない (スティーラーの本命ターゲットのため)
- **リアルタイム監視 (watch)** — Downloads / Desktop / ブラウザプロファイルの変更を検知してスキャン
- **変更履歴スキャン** — サイズと更新時刻の記録と比較し、変わったファイルだけを再スキャン
- **常駐モード (serve)** — watch + 自己スケジューラー (日次でシグネチャ更新とスキャン)
- **Windows サービス化** — LocalSystem で動作し、全ユーザープロファイルを自動で対象に展開
- **タスクスケジューラ保険** — サービスが死んでも日次ジョブが回る二重化
- **通知** — Discord Webhook + JSON レポート (任意フォルダへミラー)
- **感度レベル 1–3** — clamscan のオプションにマッピング。開発フォルダの誤検知を避ける除外指定に対応

## 動作要件

- Windows 10 / 11 (x64)
- [ClamAV for Windows](https://www.clamav.net/downloads) (ポータブル版で可、要 freshclam での DB 取得)

## ビルド

おまかせビルドスクリプト (winget で Git / Go を自動インストール → ビルド。
`-WithClamAV` を付けると ClamAV 本体とシグネチャ DB の取得、初期設定の生成まで行います):

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1 [-WithClamAV] [-WithABA]
```

`-WithABA` を付けると、共存を想定しているスティーラー向けトリップワイヤ
[a-better-antivirus](https://github.com/vulnix0x4/a-better-antivirus) もソースからビルドして導入し、
clamscan を ABA の ignore に登録します。スキャナは性質上すべてのファイルを読むため、
この登録がないと ABA からはスティーラーの一括読み取りに見えてしまいます。

手動の場合:

```powershell
go build -o wamb.exe .
```

## 使い方 (抜粋)

```
wamb scan [フォルダ...] [--level 1-3] [--changed] [--quarantine]
wamb watch                 リアルタイム監視
wamb serve                 常駐 (watch + 日次スケジューラ)
wamb update                シグネチャ更新
wamb quarantine list|restore <id>
wamb service install|start|stop|status
wamb task install [--user]|uninstall
```

設定は `%LOCALAPPDATA%\WAMB\config.json` (サービス時は任意の場所を `--config` で指定)。

設計の詳細は [DESIGN_ja.md](DESIGN_ja.md) を参照。

## ライセンス

MIT License — Copyright (c) 2026 CrossDarkrix

ClamAV 本体は含みません (外部プログラムとして呼び出すだけです)。
