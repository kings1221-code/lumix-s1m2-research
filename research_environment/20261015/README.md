# LUMIX 研究環境接手與驗證報告（2026-10-15）

本次只完成離線資源盤點與靜態分析準備。沒有連接相機、安裝或修改 APK、執行廠商程式、刷機、啟動模擬相機或展開大規模逆向。網路操作限於 Git 同步及官方工具取得。

## 分支比對與工作保全

比對的上游為 `Siegfried82/lumix-s1m2-research`，最新 main 為 `8f625cfabb31e8a71177b86e2b63a69c686de5e8`。最初 Fork `kings1221-code/lumix-s1m2-research` 的 main 為 `11b6c96602bae41a033b838524bfdb52f3452cd4`：獨有提交 0、落後上游 17。準備期間遠端 main 已由外部更新至上游同一提交；完成前重新查詢並 fetch，確認雙方差異為 0/0。本輪沒有推送 main，也未將外部更新歸為本輪操作。

| Fork 分支 | 尚未進入上游的提交 | 上游獨有提交 |
|---|---|---:|
| contrib/s5-integration-gap-audit-20261014 | b599d1b | 1 |
| contrib/s5m2-baseline-crypto-20261014 | c388d5d | 1 |
| contrib/s5m2-boot-consumer-audit-20261014 | 3362325 | 1 |
| contrib/s5m2-corpus-handoff-20261014 | 0e9e45c | 1 |
| contrib/s5-s5m2-research-handoff | 無；已在上游歷史中 | 15 |

原本地 `work` 分支無已修改、未追蹤或忽略檔案。同步前已保存完整 checkout（含 Git metadata）至 `/workspace/research-preservation/lumix-before-sync-20261015.tar.gz`，通過 gzip 檢查及 558 個歸檔項目檢查；完整 SHA-256 見 [validation.json](validation.json)。原本地分支保留，另建立 `preserve/pre-sync-20261015`，所有 Fork contrib 分支也各有 `preserve/contrib/...` 本地保留參照。

新的 `research/lumix-lab-env-20261015` 分支由原工作分支建立，以 `--ff-only` 同步至上述上游提交。本輪僅新增本目錄的環境紀錄；四個未合併提交的研究內容仍在各自分支，沒有改寫、刪除或自動合併。原 GitHub 分支均未由本輪改寫；環境記錄的研究分支另行交付。

## 本輪採用的研究入口

已讀 [README](../../README.md)、[AGENTS](../../AGENTS.md)、[需求與交接](../../S1M2固件研究需求与交接.md)、[目前狀態](../../S1M2研究当前状态.md)、[原始重現指南](../../docs/REPRODUCE.md)、[新版重現指南](../../docs/REPRODUCE_20261013.md)、[10 月 14 日更正](../../docs/PROJECT_CORRECTIONS_20261014.md)及其[實際驗證說明](../../analysis/project_corrections_20261014/验证与改动.md)。

上游已移除沒有本機 ABI 證據的 C 架構自證、虛構硬體映射與相關建置目標。本環境不沿用舊版 `make all` 或「五套 C/韌體驗證全過」說法。現行 `s1m2_firmware_project/Makefile` 提供離線測試入口，完整工具鏈測試需要原廠韌體。

目前仍有 49 項受保護 S1M2 載荷沒有驗證明文；現代認證／解碼消費者及真機完整 RAM 缺口未消失。Lab 客戶端路由不能直接當成機身 daemon 路由；修正後的 59 個方法聲明（57 固定、2 動態 URL）是歷史原檔核驗結果。本機缺少對應完整源檔，沒有重新生成該清單。

## 資源與輸入驗證

[inventory.json](inventory.json) 記錄逐項路徑、大小、完整 SHA-256、參考來源及狀態；[inventory.py](inventory.py) 可重新產生盤點。搜尋範圍為本 checkout 與 `/workspace/library-files`、`/workspace/shared`、`/workspace/scratch`；不搜尋 Git 物件或憑證目錄。

| 類別 | 本機結果 | 可支持的範圍 |
|---|---|---|
| Lab 相關公開材料 | 117 份符合 `public_sha256` | 公開檔案的位元組完整性 |
| 可讀原始碼摘錄 | 6 份 `.java.txt` 與 1 份 fallback Java，包含於上述 117 份 | 指定摘錄及有限方法內容，不能取代完整 DEX |
| XAPK／APK | 5 項歷史輸入缺失 | 只有取得記錄、大小及摘要 |
| DEX | classes.dex、classes2.dex 均缺失 | 不能重新驗證指令、分支與交叉引用 |
| ARM64 原生庫 | 18 個 `.so` 均缺失 | 現有符號、依賴與雜湊表屬歷史記錄 |
| 10 月 14 日客戶端更正所需完整反編譯檔 | 61 份缺失 | 不能重跑完整源檔核驗生成器 |
| S1M2 V1.4 原廠 BIN | 缺失 | 未執行原件封裝往返或載荷分析 |

「25 項缺失輸入」是 5 個封裝、2 個 DEX 與 18 個原生庫的合計；DEX 與原生庫可從匹配的 base／ARM64 split APK 讀取，不需要另外取得 25 個獨立下載。語言／密度 split 不阻擋主要程式碼的靜態準備。

優先補齊的精確原件如下。**這些是歷史預期摘要，沒有在本機核實不存在的原件。**

| 輸入 | 預期位元組 | 歷史 SHA-256 |
|---|---:|---|
| Panasonic_LUMIX_Lab_3.1.0_APKPure.xapk | 235867498 | `06e00657ee592870f1de106de0762637a05ee6a7cf91c916b7273305381ae477` |
| com.panasonic.jp.lumixlab.apk | 189845077 | `6ba873110d201675a905f7dac39bcda3291674e7440a484d6d5bd1a78447115f` |
| config.arm64_v8a.apk | 42944168 | `4e1a4fcbb9321bacfce69b6719146b5f8b249d5d9dded72044d23b99903fcdb4` |
| classes2.dex（base APK 成員） | 5047724 | `4147c194d9814bac0f83e2120705b6e03524a3425d2492eafdbf547898736552` |
| lib/arm64-v8a/libllc.so | 104008 | `7433d705215bb92e7a87b9005277127e5851c7a4638ca8f6a3db17d2a00927df` |

其餘 17 庫與兩個非程式碼 split 的完整摘要在 inventory.json。classes.dex 只有歷史大小 7341852 bytes，選定記錄沒有獨立成員 SHA-256，已明列為摘要缺口。

歷史取得管道為 APKPure，分發身分未獲 Panasonic 獨立確認；公開取得記錄的簽章指紋已脫敏，不能用其認證發布者。SHA-256 相等只確立檔案身分，不等於發行者身分。歷史 JADX 全量反編譯曾退出 3、報告 42 個錯誤；保存的 Java 不是完整無誤源碼恢復。`official_firmware_list.json` 是歷史 58-byte 回應，本輪沒有重新查詢服務。

## 工具與可重現安裝

目前主機為 Debian 13 / x86_64，既有 Python 3.12.14、OpenJDK 21.0.12.1、Git、unzip、file、readelf、strings 已足夠支援工具。實際新增：

| 工具 | 官方來源及驗證 |
|---|---|
| JADX 1.5.6 CLI | skylot/jadx 官方 GitHub release；ZIP SHA-256 `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974`，與官方 release asset digest 一致 |
| GNU Binutils ARM64 2.44（Debian 2.44-3） | Debian trixie 簽章 InRelease／Packages；DEB SHA-256 `6e5a9be38121213dda42189a525db01aad4dc52194b577d7d73d659a5843ce6c` |

[tool-lock.json](tool-lock.json) 保存完整來源與信任證據。下載與安裝保持 TLS、套件簽章及 SHA-256 驗證。DEB 僅解包，不執行套件安裝腳本。未安裝目前不需要的 adb、模擬器、APK 重建工具、密碼套件、QEMU 或大型逆向套件。

在儲存庫根目錄執行：

```bash
bash research_environment/20261015/install.sh
export PATH="/workspace/research-tools/bin:$PATH"
```

安裝目錄與下載快取預設為 `/workspace/research-tools`、`/workspace/tool-downloads`，可用 `LUMIX_TOOL_ROOT`、`LUMIX_DOWNLOAD_ROOT` 指定。腳本核對既有檔案後重用；遇到不同內容會停止。支援全新安裝和重複執行，沒有修改 shell 啟動檔。

JADX wrapper 使用 `JADX_CONFIG_DIR`／`JADX_CACHE_DIR` 指向工具目錄下的可寫位置；ARM64 wrapper 只為該程序加入 DEB 內 BFD/opcodes 動態庫路徑。不要直接用未設庫路徑的搬移後 Binutils。流程不需額外憑證或背景服務。

下列輸出路徑必須不存在，並位於 checkout 外：

```bash
python3 research_environment/20261015/verify_tools.py --output /workspace/NEW-tool-check
python3 research_environment/20261015/inventory.py \
  --extra-root /workspace/library-files --extra-root /workspace/shared \
  --extra-root /workspace/scratch --output /workspace/NEW-lab-inventory.json
python3 evidence/reproduce_offline.py --output /workspace/NEW-offline-replay
python3 analysis/agy_takeover_20261012/06_lab_control/verify_lab_control_codec.py
```

有原件時可用額外 `--extra-root /path/to/owned-inputs`；盤點只計算檔案／ZIP 成員摘要，不修改 APK。完整歷史生成器若固定寫回結果，應依上游指南使用 checkout 外的重放副本，不能覆寫公開原檔。

## 本次實際驗證

完整結果見 [validation.json](validation.json)、[tool_verification.json](tool_verification.json)。

- 9038 份公開歸檔 SHA-256 校驗通過。
- 合成 dump 解析、3 項真實 PTP 樣本解析及 5 項 mock 序列測試通過。
- 預設離線重放通過：26 份能力回應、144 子標籤、5 份 DAT、12 個維護函式比較（7 個歸一化一致）。
- 10 月 14 日修正後的 7 個固定 BLE 封包向量通過；沒有 BLE 或 TLS 執行階段連線。
- JADX 對官方已驗證 JAR 內的單一類別產生預期 Java；ARM64 工具對自製 `nop; ret` 合成 ELF 的組譯、標頭與反組譯檢查通過。沒有執行 ELF 或類別。
- 安裝腳本在全新工具目錄執行並重跑成功，且重新完成上述工具功能檢查。
- 原始 APK／DEX／原生庫分析、61 檔來源重建、原廠韌體往返均未執行；所需原件缺失。

新文件使用本目錄的 `SHA256SUMS` 核對；沒有重寫上游 evidence/FILE_MANIFEST.csv 或既有研究結果。

## 可立即開始與下一階段

現在可閱讀並交叉核對已驗證公開材料、fallback 更新方法與 6 份連線摘錄，重跑上述離線測試，整理送檔呼叫的證據邊界；工具也已可讀取未來提供的合法原件。這些工作仍不能獨立重驗完整 APK／native 控制流。

下一階段先從既有合法備份或可信取得管道補齊精確 base APK 與 ARM64 split（或上述完整 XAPK），保留原件、計算全摘要並重新核驗簽章來源。其後在新輸出目錄重建指定 DEX 方法與 18 庫清單，保存退出碼、錯誤及覆蓋範圍；針對 `FirmwareUpdateDetailFragment` → 實際送檔呼叫／JNI 消費端做有限追蹤。機身側現代認證／解碼處理鏈仍須對應的可信原始載入器／執行期輸入，不能由客戶端推定。

本輪到此完成準備；沒有執行上述下一階段分析。雲端設定草稿與發布另由環境設定介面處理，尚未驗證新任務還原。
