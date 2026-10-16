# A：完整容器盤點及資源界線

【已驗證】五份 APK 共 4,867 成員，每項均讀至 EOF，核大小、SHA-256 與 ZipFile CRC。原始大小／摘要見 [INPUT_MANIFEST](INPUT_MANIFEST.md)；完整 member 表見 [apk_members.json.gz](results/apk_members.json.gz)，可用 gzip 解開 JSON。

| 分包 | 成員數 | 主要內容 |
|---|---:|---|
| base versionCode 22 | 3793 | 2 DEX、resources.arsc、binary Manifest、585 個 assets 成員、2950 個 res 成員、87 個 META-INF 成員等 |
| arm64_v8a | 23 | 18 SO、Manifest 及封裝資料 |
| en | 6 | 語言資源／Manifest 等 |
| xxhdpi | 1039 | 1033 個 res 成員及封裝資料 |
| zh | 6 | 語言資源／Manifest 等 |

【已驗證】binary Manifest 原始節點與 Apktool decoded XML 次序一致，唯一明列的正規化是 base 的 uses-sdk 移到 apktool.yml。原 binary 的 minSdk 30／targetSdk 35 已獨立解析；沒有因 decoded Manifest 缺少該節點就稱原檔沒有 SDK 宣告。[原始 chunk offset、指定屬性及核對](results/manifest_binary_check.json)。

元件共 34 Activity、11 Service、5 Receiver、3 Provider；完整名稱、屬性、權限、intent action／category／data、DEX 中是否有類別及 28 個 navigation 節點在 [android_components.json](results/android_components.json)。例如 Main／DeepLink／USB attach 有各自入口；背景服務包括 LlcService、ForegroundService、LocationForegroundService、LlcMessagingService、BleLogService。宣告 exported／usesCleartextTraffic 等欄位只是宣告事實，不當作動態可達性、授權結果或所有流量明文的證明。

【已驗證】13,886 筆 resource ID 來源記錄在 [resource_ids.json.gz](results/resource_ids.json.gz)。**分包分別解碼時，base 出現 692 次 unresolved reference、427 個不同 ID；其他四包沒有該警告**。全部 APK member 已盤點，不代表資源語義全部恢復。尚未對每個未解析 ID 完成跨 split 值合併；原因不以推測定案。精確清單及日誌摘要見 [resource_decode_gaps](results/resource_decode_gaps.json)。

【已驗證】先依真實 magic 找到三個 nested ZIP：`assets/zip/rules-broadcast.zip`、`rules-localNotification.zip`、`rules-personalized.zip`，各成員完整 CRC／hash 通過。內有 rules.json（root keys version/rules）、HTML 及一份 AppleDouble 類型檔名；本輪只驗容器／JSON root，沒有執行規則或 HTML。

另一 magic 陽性為 `okhttp3/internal/publicsuffix/publicsuffixes.gz`，完整 gzip 解壓／CRC 通過；觀察到兩段 big-endian u32 長度＋UTF-8 byte sections，精確消耗解壓後整個範圍。[nested_assets](results/nested_assets.json)保留每段長度、摘要與行數，不把 container 成功提升成全部 public-suffix 語義驗收。

【尚未確認】243 個載入／反射候選的實際參數與 runtime 分派；只列已見的兩個頂層 DEX／18 個 ELF，不排除其他格式的資料、下載模組或未執行的 optional path。高熵、dat 副檔名或混淆不能單獨構成加密判斷。

第一方／第三方以**已核 namespace、Manifest 元件、實際呼叫、70 份 META-INF version 宣告與 ELF 依賴**分層記錄；未把全部短包名歸為第一方或第三方，也未宣稱 .so 與某個上游 release 位元組相同。
