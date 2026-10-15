# 離線研究環境與輸入驗證（2026-10-15）

本分支完成資源盤點、輸入身分核對與最小靜態工具準備。推進的是 **Lab 客戶端證據 → DEX/JNI → 後續固件處理鏈** 的可信輸入準備；沒有開始批量反編譯、函數分析或密碼試驗，也沒有恢復 S1M2 受保護載荷。

## 驗證結論

| 對象 | 本次實際結果 | 證據界線 |
|---|---|---|
| Fork main | 從 `11b6c96602bae41a033b838524bfdb52f3452cd4` 快轉到 `8f625cfabb31e8a71177b86e2b63a69c686de5e8`，與上游差異 0/0 | 原本落後 17、獨有 0；沒有強制更新 |
| 個人研究分支 | 四個未合併提交完整保留；另建本機 preservation refs | 沒有把它們自動併入 main |
| LUMIX Lab 3.1.0 APK | 五個檔案大小及完整 SHA-256 全部符合保存的 delivery manifest | 沒有重新向商店驗證來源，沒有重做 APK 簽章驗證 |
| DEX | 兩個提取檔與已核 APK 內成員 SHA-256 完全一致；DEX header 長度、SHA-1、Adler32 均通過 | 沒有執行或重新反編譯 DEX |
| ARM64 原生庫 | 18/18 提取檔與 ARM64 split 成員完全一致；均為 ELF64 little-endian、EM_AARCH64 | 只讀 ELF header，沒有載入庫或分析函數 |
| 既有 JADX 輸出 | 13,496 個 Java 檔，其中 Panasonic 命名空間 529 個 | 檔案數是本次盤點；歷史「42 個反編譯錯誤」未重跑 |
| 10/14 引用的 61 份源碼 | 60 份在僅 CRLF→LF 正規化後與更正紀錄完全一致；1 份不同 | `p062f5/P2.java` 不可作為歷史精確副本 |
| 相關公開證據 | 207 份：13 份工作樹位元組雜湊相同，194 份 Git blob 相同且工作樹僅有 CRLF 差異 | 驗證歸檔一致性，不重現報告中的實驗 |
| 輔助 S5M2 固件 | V2.0、V3.1、V3.2、V3.7 四個 BIN／ZIP 成員雜湊與保存的 corpus profile 相同 | 僅計算雜湊；不替代 S1M2 原檔或重新背書歷史來源 |
| 工具環境 | 四個官方封存物 SHA-256 通過；8 項環境檢查通過 | 只執行可信工具的版本／說明、合成 RET 反組譯與 ELF header 讀取 |

主要機器證據：[資源清單](final/inventory.json)、[工具驗證](environment_verification.json)、[Git 同步與保留紀錄](git_sync.json)。`historical_replay_complete=false` 是預期的缺口狀態，不能把盤點成功解讀為全部研究已重現。

## Git 差異與保留方式

最初工作目錄只有空 `.git`，沒有本機提交或研究檔案。登記 `origin` 為個人 Fork、`upstream` 為指定上游；完整 fetch 未使用 prune、reset、rebase 或強制推送。先建立本機 main，再執行 `merge --ff-only upstream/main`，最後建立 `codex/offline-research-environment-20261015`。

本機 HTTPS push 缺少憑證，沒有改動遠端；改用已連接 GitHub 的 API，指定原 main 的 `expected_sha` 與 `force=false` 完成同步，再 fetch 核對差異 0/0。原始 main 固定保存在 `preservation/20261015/fork-main`，五個原有 contrib 分支也各有 preservation ref。

| 尚未進入上游 main 的原有分支 | 獨有提交 |
|---|---|
| `contrib/s5-integration-gap-audit-20261014` | `b599d1b99a6f8e0b0cb866f243eb05c67ffdfeae` |
| `contrib/s5m2-baseline-crypto-20261014` | `c388d5d4d6c344b26f707b3fa66f84aa1b43e629` |
| `contrib/s5m2-boot-consumer-audit-20261014` | `3362325de9e36e067f1826575f0fffde24ed98fd` |
| `contrib/s5m2-corpus-handoff-20261014` | `0e9e45c54a6cadf9095a612fe03d34839ef638ff` |

`contrib/s5-s5m2-research-handoff` 的提交已在上游歷史內。後續 fetch 額外發現 `research/lumix-lab-env-20261015`；它與工作期間出現的未追蹤 `.codex-remote-attachments/`、`downloads/` 均保留原狀，沒有納入本分支的交付。

## 已讀取的接續與更正入口

- 根 [README](../../README.md)、[AGENTS](../../AGENTS.md)、[需求與交接](../../S1M2固件研究需求与交接.md)、[目前狀態](../../S1M2研究当前状态.md)。
- [原重現指南](../../docs/REPRODUCE.md)、[完整重現與缺口](../../docs/REPRODUCE_20261013.md)。
- [2026-10-14 更正入口](../../docs/PROJECT_CORRECTIONS_20261014.md)、[實際改動及驗證](../project_corrections_20261014/验证与改动.md)、[修訂後 Lab 報告](../agy_takeover_20261012/06_lab_control/report.md)與其機器輸入清單。
- [Fork 的 Lab 3.1.0 分析](../../docs/LUMIX_LAB_S5M2_APK_ANALYSIS.md)、本機原有 ANALYSIS／VERIFICATION／BREAKTHROUGH 記錄。

目前 S1M2 V1.4 的「62 項已提取、49 項 flags=3 未有驗證明文」仍是上游研究狀態；本機沒有取得該原檔，沒有重新驗證此封裝。10/14 修正後的 59 個客戶端宣告不能稱作機身 daemon 路由全集；`destination_raw` 不能當已證實 RAM 地址；通用 QEMU RAM 不能作為相機 RAM。舊功能解鎖建議及動態測試建議不構成本輪授權。

## APK、DEX 與來源區分

`SOURCE_ROOT` 指原有 `s5m2-apk` 研究目錄。本輪只讀該目錄，沒有搬移、改寫或安裝其中的 APK。實際本機路徑另存於忽略追蹤的 `.research-local/local_paths.json`。

| Google Play 配置檔 | Bytes | SHA-256 |
|---|---:|---|
| `com.panasonic.jp.lumixlab-22.apk` | 189845077 | `6ba873110d201675a905f7dac39bcda3291674e7440a484d6d5bd1a78447115f` |
| `…-config.arm64_v8a.apk` | 42944168 | `4e1a4fcbb9321bacfce69b6719146b5f8b249d5d9dded72044d23b99903fcdb4` |
| `…-config.en.apk` | 78233 | `6288e4ea41dce76389814d191eb39afed7a5171d8f80116612c0f23fe98e6ca5` |
| `…-config.xxhdpi.apk` | 9983302 | `6b62ec477edfa3673b87c7f361721fb4707a3c2d313d45c70ada1c8774515b39` |
| `…-config.zh.apk` | 205209 | `626fab49109927bba388a81370b80d509717424033a7caedfb7b96e2557ca18f` |

| Base APK 的 DEX | Bytes | SHA-256 |
|---|---:|---|
| `classes.dex` | 7341852 | `02782fe6cf962788d1e5e76f707fc9d5e45669c205eaafee9bb8c50f2f5810ff` |
| `classes2.dex` | 5047724 | `4147c194d9814bac0f83e2120705b6e03524a3425d2492eafdbf547898736552` |

18 個原生庫包括 `libllc.so`、`libcube_merge.so`、`libtechorfilter.so`、`libcrypto.so`、`libssl.so`、`libonnxruntime.so` 及影音庫；完整名稱、大小、SHA-256 與 ELF header 在資源清單中逐項保留。這些是 Android App 的 ARM64 程式，不能據此推定相機固件的 ISA。

保存的 Google Play delivery manifest 已複製為[固定參考](references/google-play-delivery-integrity.json)。它是歷史取得紀錄，本輪的 SHA 驗證證明本機位元組與紀錄一致。鏡像取得報告中的全零占位憑證指紋不能採用；本機歷史 signature.txt 另記 `6e8e62b2206759c021bf316feda8bfd814007f46aba8f1fd5097aa40c9017e03`，本輪仍未重新驗證簽章或獨立建立 Panasonic 簽章信任鏈。

Downloads 中另有三份 20261015 交接 ZIP，完整 SHA 相同，每份僅七個文件／腳本／清單成員，沒有 APK、DEX、SO 或固件原檔。只讀盤點見 [handoff_archives.json](handoff_archives.json)，未執行包內腳本。

歷史 APKPure XAPK 使用 `en + mdpi`，現有 Google Play 配置是 `en + zh + xxhdpi`。base／ARM64／en 的已記錄摘要相同，不能將兩組配置的完整來源或完整性混為一談。

## 已安裝的最小工具環境

全部新增工具位於忽略追蹤的 `.research-local/`，沒有變更全機 PATH、Java 或 Python 安裝。

| 工具 | 版本 | 用途與官方來源 |
|---|---|---|
| JADX | 1.5.6 | DEX／AXML 靜態檢視；[官方發佈](https://github.com/skylot/jadx/releases/tag/v1.5.6) |
| Eclipse Temurin JRE | 21.0.12.1+1，Windows x64 | 執行 JADX；[官方發佈](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1) |
| pyelftools | 0.33 | ELF 資料解析；[官方 PyPI](https://pypi.org/project/pyelftools/0.33/) |
| Capstone | 5.0.9 | ARM64 靜態反組譯；[官方 PyPI](https://pypi.org/project/capstone/5.0.9/) |

宿主使用 Codex 隨附 CPython 3.12.14／Windows x64；版本及工具封存物完整雜湊見 [toolchain.lock.json](toolchain.lock.json)、[requirements.lock](requirements.lock)。JADX／JRE 從舊的官方封存物唯讀複製，兩個 wheel 從官方 PyPI 發佈位址取得；沒有使用舊目錄中的不明執行檔。

沒有安裝本階段不需要的 Ghidra、Android SDK、ADB、QEMU、GNU MN10300 工具鏈或密碼枚舉依賴。`apksigner` 的完整簽章驗證、舊消費者重放及歷史密碼試驗不在這個最小工具環境的已驗收範圍。

## 重建與重跑

從倉庫根目錄執行，準備可信的 Windows x64 CPython 3.12。以下 `$pythonPath` 請填入本機 Python 執行檔，`$sourceRoot` 請填入原研究目錄。使用完整鎖定 URL，沒有使用 latest 重新選版。

```powershell
$pythonPath = 'C:\path\to\python.exe'
$sourceRoot = 'C:\path\to\s5m2-apk'

# 首次缺少官方封存物時，明確允許下載；只從鎖定的官方 URL 取得工具。
& .\analysis\offline_environment_20261015\setup.ps1 -Python $pythonPath -AllowDownload

# 已保留 .research-local/downloads 的機器可完全離線重建／檢查。
& .\analysis\offline_environment_20261015\setup.ps1 -Python $pythonPath

$researchPython = '.\.research-local\venv\Scripts\python.exe'
& $researchPython -I analysis\offline_environment_20261015\verify_environment.py `
  --source-root $sourceRoot --output .research-local\NEW_environment.json
& $researchPython -I analysis\offline_environment_20261015\audit_resources.py `
  --source-root $sourceRoot --output .research-local\NEW_inventory
```

也可用 `-Cache C:\path\to\official-archives` 提供只讀封存目錄。bootstrap 預設不連線；所有封存物先核 SHA-256，已安裝的 Java/JADX 逐成員對回鎖定 ZIP；pip 安裝固定 wheel，使用 `--no-index --no-deps --only-binary --require-hashes`。不覆寫既有結果；`NEW_*` 路徑必須不存在。

第一次離線重跑遇到 sandbox 臨時目錄清理警告，安裝結果仍成功。setup 已把 pip 臨時檔限制到 `.research-local/tmp` 並停用快取；再次離線重跑確認此修正。初期只核原始位元組的盤點輸出保留在 `.research-local/development-history/`，交付以 `final/inventory.json` 的逐類結果為準。

若要重現本次額外四份固件的雜湊盤點，為 audit 逐次加入 `--firmware PATH`：S5M2 V2.0 BIN、V3.1 BIN、V3.2 ZIP、V3.7 ZIP。程式只串流讀取／雜湊 ZIP 的 BIN 成員，不提取或執行固件。比對 profile 固定來自個人分支提交 `0e9e45c54a6cadf9095a612fe03d34839ef638ff`，副本見 [references/s5m2_corpus_profiles.json](references/s5m2_corpus_profiles.json)。省略這些參數時不宣稱核對了這四份固件。

未來若補齊 S1M2 V1.4，可加入 `--s1m2 PATH` 做精確長度與 SHA 檢查。XAPK／mdpi 和機身側缺口是本次人工搜尋的日期快照，重跑程式不會自動擴大搜尋整個磁碟。

既有 Git 的 `core.autocrlf=true` 來自應用隨附 Git 設定，本輪沒有更改它。公開證據的差異必須先對 Git blob；Java 僅正規化換行後的吻合另列為 `verified_normalized_lf_reference`，保留原 SHA。沒有改寫原始源碼以製造吻合。

## 缺口與下一階段

以下「缺少」只涵蓋本次搜尋的工作區、使用者 Documents／Downloads／Desktop 及已找到的研究目錄，不表示整部電腦或其他磁碟都沒有。

| 缺少或不吻合的輸入 | 精確參考 | 影響 |
|---|---|---|
| S1M2 V1.4 原始固件 | 171867648 bytes；SHA-256 `e91620854dd435131e03178076b486767cf9a3d2cfd62d173c537cb2afe9ea0f` | 無法在本環境重算 62 項目錄、CRC 與提取結果 |
| 歷史完整 XAPK | 235867498 bytes；SHA-256 `06e00657ee592870f1de106de0762637a05ee6a7cf91c916b7273305381ae477` | 無法重現該鏡像包的封裝與全部配置 |
| XAPK 的 mdpi split | 2997638 bytes；SHA-256 `c9ef5805000fb77ef3a97e9f5bc3ce730fc77f7db7fe19cb56c9dc1b8fccefbe` | 不影響現有 Google Play DEX／ARM64 分析 |
| 精確的 `p062f5/P2.java` 歷史副本 | 預期 LF SHA `01eab5cc6be73a9a8907e6a8bef667b53857ff9730b72d883c5c9a3caa746d03`；現有 LF SHA `47d4c21ad0868a665a532dff773d1ee6058f3572a48e79df04446045b66547f6` | 不可直接宣稱完整重現 10/14 的 61 源碼輸入；可從已核 DEX 重新驗證 |
| S1M2 受保護明文、實際 daemon／部署 DTB、真機 RAM | 尚無可核對的原始輸入摘要 | 無法重建現代固件認證／解碼消費者或機身載入映射 |

可立即開始的後續工作依序為：

1. 針對固件傳輸／認證相關方法做小範圍 DEX／Smali 核對，先處理 P2 源碼差異及歷史 42 個失敗方法中相關項目；保留版本、方法與輸出雜湊。
2. 以已核 18 個 ELF 做 JNI 匯出／匯入與呼叫邊界盤點，再選與固件處理有直接關聯的函數。現有 Capstone／pyelftools 已可用。
3. 比對更正後客戶端證據與上述實際程式，列出機身側需要的 daemon、更新消費者及原固件輸入，不能由 App 端點推定機身內部實作。
4. 原 S1M2 V1.4 補齊並通過精確 SHA 後，先做目錄／CRC／逐項 SHA 基線，再討論有新依據的靜態消費者追蹤。現有四份 S5M2 輔助語料可作受限對照。

本輪沒有連接相機、送出相機／BLE／USB 請求、刷機、修改 APK、啟動 APK／固件／客體映像或執行外部交接包內腳本。下載範圍只有指定 Git 倉庫與官方工具依賴。
