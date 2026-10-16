# LUMIX Lab 全面逆向工程技術總報告：A／B／C 中期版

日期：2026-10-16。主要樣本：**LUMIX Lab 3.1.0，versionCode 22**。分支 `codex/lumix-lab-full-reverse-20261016`，基線為第二階段 `2e076ce1e455fec7ed7ea0715b2347378f837c45`。這是全 App 結構索引及選定程式鏈的中期成果，**不宣稱完整 App 語義、原始碼或全部 ARM64 函式已恢復**。

本輪新授權允許研究整個 App，優先 A／B／C；D／E／F／G 的全面展開仍等待使用者審查。本輪必要的資源解壓、PNG CRC 控制及既有通訊資料交叉引用是 A／B／C 的驗證依賴，不是啟動新的全域密碼學或通訊掃描。

## 新增成果與更正

1. 【已驗證】原 25 個 APK／DEX／ARM64 SO 身分一致；完整讀取 5 個 APK 的 **4,867 個成員**，保存各自大小、SHA-256、ZIP CRC、壓縮方法與格式證據。三份內嵌 ZIP 及一份 gzip 另有實際容器解析結果，不從熵推定加密。
2. 【已驗證】補齊 **14,812 類別、48,914 欄位**；沿用既有 **76,901 方法、349,415 invoke 位置**，建立可查詢的類別／方法／欄位／caller／callee 資料庫。另索引 **73,540 個 DEX 字串的 ID／位置／SHA**，公開版不散布原始常數或憑證值。
3. 【已驗證】5 份原始 binary Manifest 與 Apktool 的節點順序核對通過，但需明確扣除 Apktool 搬到 YAML 的 uses-sdk。原 binary 可核 minSdk=30、targetSdk=35、versionCode=22。宣告有 **34 Activity、11 Service、5 Receiver、3 Provider**，另有 28 個 navigation 節點及 13,886 筆 resource ID 記錄。
4. 【已驗證】建立 10 組實際入口與跨模組呼叫關聯、680 個指定非同步 API 位置、243 個反射／載入候選位置。它們是索引，不是所有動態分派已解決。共享 R8 Callable `g5/k` 還同時服務 App 與 Lottie；本輪以 selector 核對，避免把某一 case 的 native 呼叫套到所有 caller。
5. 【已驗證】18 個 ELF 補全 Header、sections、segments、依賴及 init-array metadata，沿用相同摘要的既有符號清單。新增 `libcube_merge.so` 的 9 個選定函式，及 `libllc.so` 的兩個定點交叉核查；**1,543 條新核查指令位元組與原 ELF 相符**。加上第一階段，共 61 個不同選定函式有 Ghidra 證據，不能稱為 18 庫全面語義恢復。
6. 【與既有結果衝突】一次 Ghidra caller C 漏顯示 `cube_merge_files → 0x4e60` 的第三參數。原 ARM64 在 ELF VA `0x5260` 設 `x2=sp+0x38`，再呼叫，並將同一結構送往 writer。以唯讀 Ghidra 專案中的分析型別修正後，C 明確出現第三參數；原 SO 未改動。
7. 【已驗證】24 個 JADX 失敗方法維持原 CFG 證據，本輪補出 `l0/h.D` 的 PNG eXIf／iTXt metadata 重寫**部分語義**，與 Baksmali 原指令序列吻合。`NativeOnCompleteListener.onComplete` 也完成獨立 Baksmali 序列核對。沒有把其餘 23 項標成已完成高階恢復。
8. 【尚未確認】兩個 JNI 未決宣告仍未完全解決：splitYuv 的 C++ 改名實作有資料流、沒有普通 JNI 名稱綁定證據；Google Task callback 的 Java 建立及完成回調已定位，但這 18 庫沒有已核綁定實作。詳見 [JNI_NATIVE_MAP](JNI_NATIVE_MAP.md)。

## 最重要的新程式鏈

【已驗證】`EditActivity.E0(Uri)` 在一條條件路徑建立 selector=1 的 `g5/k` Callable；該 case 的 CU `0x213` 呼叫 `LlcApplication.mergeCubeFiles(String,String,String)`。`libllc.so` ELF VA `0x122ac` 取得三個 JNI UTF 字串，交給其真實依賴 `libcube_merge.so:cube_merge_files`，再釋放字串。後者讀取兩個 cube，組合網格、寫出第三個檔案並清理記憶體。輸入／輸出、回傳碼、地址與限制見 [ARM64_ANALYSIS](ARM64_ANALYSIS.md)。

```mermaid
flowchart LR
  E[EditActivity.E0 條件分支] --> C[g5.k selector 1 Callable]
  C --> J[LlcApplication.mergeCubeFiles]
  J --> L[libllc 0x122ac]
  L --> M[libcube_merge 0x51d0]
  M --> R[讀取兩份 LUT 資料]
  R --> G[組合網格與插值候選]
  G --> W[寫出第三檔與清理]
```

這是有原始參數／消費者證據的影像 LUT 路徑；**不是韌體解碼器**。另一處 CRC32 的實際輸入是 PNG chunk type＋metadata，亦不能改稱韌體摘要驗證。

## 十個審查問題

| 問題 | 本輪答案及界線 |
|---|---|
| 有哪些完整功能模組？ | 可確認存在的入口組涵蓋啟動／權限、配對連線、遠端控制、圖庫傳輸、影像／LUT、模板、社群、直播、更新、背景通知；**沒有宣稱這些模組的每條功能路徑已完整恢復**。見功能圖。 |
| 各模組由哪些類別／native 組成？ | 全 DEX 結構、元件、navigation、10 組入口與可見 storage／communication／native 關聯可查；混淆所有權與未解 callback 保留未知。 |
| 主要 Java／JNI／ARM64 鏈？ | 保留前階段媒體／更新鏈；新增上述經 discriminator 核對的跨庫 LUT 鏈、splitYuv 的實作資料流與 Google Task callback。 |
| 實際密碼學與資料轉換？ | 本輪證實的是 PNG CRC 消費者、LUT 讀寫與插值候選、ZIP/gzip 格式，以及先前 TLS peer fingerprint；全域 D 還未展開。 |
| 新韌體驗證／解密路徑？ | 本輪沒有建立新的可驗證韌體位元組消費者；F 的反射／間接路徑逐站核查尚未進行，不能把此結果稱為全 App 不存在。 |
| 哪些格式能解析／重建？ | 五個 ZIP 容器與三個 nested ZIP 目錄／CRC、binary XML 節點／指定屬性、DEX 結構、ELF 結構、gzip 解出兩段長度資料、合成 PNG iTXt CRC。未完成整體 APK 重建、全部資源合併、LUT 數學等價或機身固件解碼。 |
| 受哪些限制？ | 427 個 unique resource reference 仍未解析、23 個其他失敗方法未新增語義、全部間接分派、原生大型庫內部與外部 Google native 綁定；見 UNRESOLVED。 |
| 覆蓋率？ | 結構範圍可精確計數；沒有把語義換成一個假的總百分比。見 COVERAGE。 |
| 下一步具體問題？ | 精確 split-resource 合併、LUT 插值等價控制、複雜失敗方法、動態分派及兩個綁定缺口；D／E／F／G 是否展開由使用者決定。 |
| 是否只剩相機端能回答？ | 韌體接收／認證／解碼仍缺相機實作；整個 App 還有可做的靜態問題，不能把全部 App 研究稱為已到盡頭。 |

## 閱讀入口及交付

- [樣本與完整 SHA](INPUT_MANIFEST.md)、[APK 結構](APK_STRUCTURE.md)、[功能模組](FUNCTION_MODULE_MAP.md)
- [DEX 與反編譯進度](DEX_ANALYSIS.md)、[JNI](JNI_NATIVE_MAP.md)、[ARM64](ARM64_ANALYSIS.md)
- [密碼學／編碼現有種子](CRYPTO_AND_ENCODING_MAP.md)、[通訊現有種子](COMMUNICATION_MAP.md)、[更新既有模型](FIRMWARE_UPDATE_MAP.md)
- [未解問題](UNRESOLVED.md)、[覆蓋](COVERAGE.md)、[重現](REPRODUCE.md)、[進度](PROGRESS.md)

原 APK／DEX／SO／固件、完整 Java／Smali／Ghidra C、工具快取及 SQLite 留在 `.research-local/full_reverse/` 或先前忽略目錄；公開的是自行編寫腳本、結構 metadata 與必要精簡證據。未取得第三方服務憑證、未繞過存取控制、未連相機、未執行目標 App／原生程式。中期交付後停止，不自動擴大 D／E／F／G。
