# WAMB (Win Anti Malware Blocker) 設計メモ (v0.6)

作成: 2026-11-21 / 状態: 主要決定は確定 (2026-11-21 たろうさん決定)
名称: **WAMB (Win Anti Malware Blocker)** — たろうさん命名。当初案の WAMD (…Defender) から変更し、Microsoft 製品と紛らわしい "Defender" を外した。
実装言語: **Go** (単一 exe、Windows サービス化しやすい)

## 目的

- ClamAV (Windows 版) を「呼ばれるまで何もしない安全なセカンドスキャナ」として運用し、その管理を自作 Go ツールで担う。
- Defender が土台という現行構成は変えない。常時監視 (オンアクセス) は持たない。
- カスペルスキーを外した理由 (開発環境で重い・誤検知がひどい) を再発させない: 開発フォルダには干渉しない、最初は検出のみで自動削除しない。

## 構成

```
[管理ツール (Go, Windows サービス)]
  ├─ スケジューラ (サービス内 ticker)
  ├─ freshclam 実行 (シグネチャ更新)
  ├─ clamscan 実行 (対象フォルダを絞った定期スキャン)
  ├─ 結果パース → ログ (JSON + 人間可読) / 通知
  └─ 設定ファイル (1枚) の読み込み
[ClamAV 本体] clamscan / freshclam (公式 Windows 版)
```

## 動作形態 (確定: 二重スケジューリング)

- **主: Windows サービスとして常駐**し、自己スケジューラ (内部 ticker) で freshclam とスキャンを回す。Go 側は `golang.org/x/sys/windows/svc` (または kardianos/service) で実装。
- **保険: タスクスケジューラにも同じジョブを登録**し、サービスが落ちている/止められている場合でも単発 CLI (`wamd scan` / `wamd update`) が定期実行されるようにする (たろうさんの「万が一に備えて保険」案)。
- 二重化の副作用対策: スキャンと更新は **名前付きミューテックス + ロックファイル**で同時実行を禁止する。サービス側とタスク側がぶつかったら後発は「実行中」と記録して何もしない。
- サービスは SYSTEM で動く前提。そのため設定ファイルと exe は管理者のみ書き換え可能な場所 (Program Files / ProgramData 配下) に置く。

## スキャン方針

- 対象 (初期): Downloads、デスクトップ、ブラウザのダウンロード先、受け入れフォルダ (C:\Muse 等)。設定で増減可能。
- **検出のみ**: `--remove` / `--move` は使わない。検出は一覧化して報告まで。隔離への移行は誤検知の癖を見てから別途判断。
- PUA 検出 (`--detect-pua`) は既定 OFF (開発ツール類の誤検知を避ける)。
- 除外 (初期): msys64、ビルド出力フォルダ、プロジェクトの作業ツリー、Go のキャッシュ等。
- **clamd は使わない (確定)**: たろうさんに「以前使った時めちゃくちゃ重い」印象があり、DB 常駐のメモリ消費も見合わない。clamscan 都度実行のみ。起動時に DB を読む分は夜間スケジュール前提で許容する。

## 更新方針

- freshclam を 1日1回 (既定) サービスから実行。結果はログへ。
- rfxn (maldet) の ClamAV 形式シグネチャを任意で追加可能にする余地を残す (Webシェル検出の強化)。初期は ClamAV 公式 DB のみ。

## 通知 (確定: Discord Webhook + Muse 可読レポート)

- **Discord Webhook**: 検出時に通知 (件数、ファイルパス、シグネチャ名、スキャン ID。ファイル内容は送らない)。検出ゼロの定期スキャンは通知しない。
- **Muse が見れる形**: 各スキャンの結果を JSON レポートとしてローカル (ProgramData) に保存し、さらに **最新レポートを C:\Muse\wamd\ へミラー**する。C:\Muse は擬似VNC v2 の許可フォルダなので、Muse が WebDAV/API 経由で読んで検出を把握できる。
- ログ (JSON + 人間可読) は常時残す。Muse Mail 経由の通知は Go ツールからは直接送れないため対象外。

## ABA (a-better-antivirus) との共存

- 大量ファイルを読むスキャンは ABA の sweep 判定 (critical) に当たるため、4200M では **管理ツールの exe を `aba ignore` に登録する**ことを導入手順に含める。
- 逆に ABA の餌ファイルはスキャン対象フォルダ (Desktop/Documents) に置かれるため、ClamAV 側で餌を検出扱いしないよう、必要なら除外に加える。

## 展開順

1. Phase 1: CLI 単発版 (スキャン実行 + レポート生成まで、サービス化なし) を 4200M で試す。
2. Phase 2: サービス化 + スケジューラ + freshclam 自動化。4200M で数日運用し誤検知と負荷を見る。
3. Phase 3: 通知追加、問題なければメイン機へ展開 (メイン機は 24H2 固定運用に影響しないことを確認してから)。

## Phase 1 追加要件 (2026-11-21 たろうさん指定)

- CLI 引数でスキャン対象フォルダを指定できる
- 検知度合い (感度レベル) を変更できる → clamscan のオプション群にマッピング (低/標準/高)
- 除外ファイル・除外フォルダを指定できる (引数と設定の両方)
- 隔離フォルダを指定でき、検出ファイルの隔離は明示操作 (--quarantine 指定時 or 後から scan-id 指定) でのみ行う (既定は検出のみ)
- 検出時の通知 ON/OFF を選べる
- **ブラウザのクッキー (とログイン情報) は必ず監視対象**: Chrome/Edge/Brave/Firefox のプロファイル配下 (Cookies / Login Data 等) は保護対象として常時監視に含め、除外指定が当たっても無効化できない (警告を出す)
- 定時スキャン (スケジュール設定。実行の担い手は二重スケジューリング: サービス自己スケジューラ + タスクスケジューラ)
- 軽量なリアルタイムスキャン: 対象フォルダを監視し、変更されたファイルだけを間引いて (debounce) スキャンする `watch` モード (Phase 1 はフォアグラウンド実行、サービス組み込みは Phase 2)
- 変更履歴スキャン: ファイルの size/mtime を状態ファイルに記録し、前回から変わったファイルだけをスキャンする増分モード (`scan --changed`)

## 4200M 試運転の実測 (2026-11-21 未明、Muse が実施)

- 配置: ClamAV 1.5.5 ポータブル zip (公式 clamav.net、215.4MB) を `C:\Muse\clamav\clamav-1.5.5.win.x64\` に展開 (管理者不要)。freshclam で main/daily/bytecode の DB 取得完了。wamb.exe は `C:\commandline\wamb.exe`。
- **Defender との相互作用 (重要)**: EICAR テストファイルは clamscan が読もうとした瞬間に Defender のリアルタイム保護が読み取りを遮断 (LibClamAV エラー 225 = ERROR_VIRUS_INFECTED) し、その後 Defender 自身がファイルを隔離・除去した。つまり Defender 有効環境では、既知マルウェアの実ファイルはセカンドスキャナが読む前に Defender が処理する。多層防御としては正しい挙動で、WAMB の価値は「Defender が見ない場所・形式・カスタムシグネチャ」側に寄る。
- 検出パイプラインの検証は **カスタムシグネチャ** で実施 (database に .ndb を追加し、無害な文字列 WAMB-TEST-STRING を検出): scan 検出 (終了コード1) → --quarantine で隔離 → list 表示まで実機確認済み。これは rfxn 等の追加シグネチャ運用がそのまま効くことの証明にもなる。
- clamscan の DB ロードは 4200M で約20〜40秒/回。定時・変更分スキャンでは許容範囲、watch のバッチ間隔はこれを前提に設計する。

## Phase 2 実装 (2026-11-21 Muse が実装)

- `wamb serve`: 常駐モード。watch (リアルタイム監視) を内包し、自己スケジューラーで設定時刻に update (freshclam) と scan を実行する。各ジョブは単一実行ロックを取り、タスクスケジューラ側と競合しない。実行済み日付は serve-state.json に記録し、再起動で再実行しない。
- `wamb service install|uninstall|start|stop|status`: Windows サービス "WAMB" の管理 (golang.org/x/sys/windows/svc + mgr)。サービスは LocalSystem で `serve --config <ProgramData の設定>` として起動する。status は標準ユーザーでも引けるよう sc.exe フォールバック付き。
- `wamb task install [--user]|uninstall`: タスクスケジューラ保険ジョブ (WAMB Update / WAMB Scan、毎日、設定時刻)。既定は SYSTEM 登録 (管理者必須)、--user で現ユーザーのタスクとして登録。
- **SYSTEM 時のプロファイル展開**: サービス (SYSTEM) には自ユーザーのプロファイルが無いため、C:\Users 配下の全プロファイルについて Downloads/Desktop をスキャン対象に、ブラウザ保存先 (AppData\Local / Roaming から構築) を保護対象に自動追加する。
- メイン機展開: `setup-wamb-mainpc.ps1` (管理者で1回実行) が ClamAV 公式 zip のダウンロード (サイズ照合付き) → C:\Program Files\ClamAV へ配置 → 初回 freshclam → C:\Program Files\WAMB\wamb.exe 配置 → C:\ProgramData\WAMB\config.json 配置 → サービス登録・開始 → タスク登録、を行う。資材一式はメイン機 WebDAV の C:\Muse に配置済み (wamb.exe / setup-wamb-mainpc.ps1 / wamb-mainpc-config.json)。

### Phase 2 実測 (2026-11-21 03:00〜03:15、4200M 実機)

- `wamb service status`: 標準ユーザーでは mgr.Connect が Access denied になるため sc.exe フォールバックを追加し、「not installed」を正しく返すことを確認。
- `wamb task install --user`: WAMB Update / WAMB Scan の登録・schtasks での確認・uninstall まで通過 (SYSTEM 登録は管理者実行時のみ、メイン機の setup スクリプト側で実施)。
- `wamb serve` (テスト設定、update 03:10 / scan 03:13): 起動直後に watch が4フォルダ (Downloads/Desktop/Edge/Brave) を監視開始。Downloads へのキャリア投下を watch が検出 (03:10:07)。03:10 に signature update done、03:13 に scheduled scan (6ファイル・1検出) が発火し、serve-state.json に両ジョブの日付が記録された。再起動時の二重実行防止もこの状態ファイルで担保。
- メイン機資材 (wamb.exe / setup-wamb-mainpc.ps1 / wamb-mainpc-config.json) を WebDAV の C:\Muse へ配置済み (全て PUT 201)。残るは本人の管理者実行のみ。
