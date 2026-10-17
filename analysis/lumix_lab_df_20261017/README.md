# LUMIX Lab 3.1.0：D／F 高優先級技術報告

2026-10-17，versionCode 22。在 `codex/lumix-lab-full-reverse-20261016` 延續 A／B／C，基線 `0de47d702ef058cea3b39dabf521a7754f0003a1`。本輪完成全索引使用盤點、選定實際消費者、動態呼叫補查與優先缺口；**不宣稱所有 SDK／Native／反射語義已完整恢復**。依新授權完成本次報告後暫停，E／G 僅準備入口與測試候選。

## 本輪實際新增

1. 【已驗證】從既有 76,901 方法／349,415 invoke 查出 **5,375 個指定 API 使用位置、1,630 個方法**，含 Java security／crypto、TLS、CRC／壓縮、Base64、JSON、Parcel、物件序列化及 ByteBuffer。原始 DEX 的 method_ids、invoke opcode、register operands 獨立交叉核對；這是完整指定模式清單，不是 5,375 條完整資料流。另以 73,540 個既有 string ID 的摘要查詢，對 73 個允許的演算法標籤 ID 回核原始位元組。
2. 【已驗證】整理 **14 個有範圍的 Java 消費者**與 83 個 factory 參數位置，分開記錄輸入、參數、Caller、輸出、消費者及運行期未知。證實的用途包含相機 TLS 憑證指紋、快取檔名、SDK 識別／OAuth、ZIP、HTTP header 編碼及 ASCII 篩選；不能把它們一律叫成韌體加解密。
3. 【已驗證】原 243 個反射／載入候選全數分類；CFG 恢復 **95 個字面目標**，另核實一個 FFmpeg 載入迴圈的 **7 庫有限集合**。合計 96／243＝**39.51%** 有字面或有限集合目標證據；147 個仍未精確解決，沒有任何運行期執行證明。另發現舊模式未涵蓋的 **69 個** Constructor／Proxy／MethodHandle 等位置，獨立建檔，沒有藏進舊分母。
4. 【已驗證】R8 共用 `g5/k` 的五個 caller 分開對應 selector。新增確認 selector 2：`h5/l.b → g5/k.call → GalleryInfoEntity.getFileRating → writeVideoRatingJni → libllc:0x160c8 → writeVideoRating`；其 JNI 字串取得／釋放與 int 回傳沿用並核對原證據。selector 1 的 LUT 合併與其他三個入口不混用。
5. 【已驗證】18 庫中，透過真實 relocation／PLT／BL 找到 **2,428 個指定 import 呼叫位置**，並用 Capstone 交叉解碼。新增 `libavformat.so` 的 TLS open／read／write 與條件 inflate 四個函式；9 個 cube 函式補出明確工具 CFG。13 函式共 **1,752 指令列**回核原 ELF，另讀出 12 指令的 TLS I/O helper，確認它還會更新 flags，不能視為純 getter。
6. 【已驗證／模型範圍】LUT 六區域四角點加權與獨立四面體公式在 **1,044 個合成模型案例**相符，另有不同尺寸組合及 27 行輸出控制。原 ARM64 顯示間距是 float32 除法後轉 double、索引使用 `FCVTMS` 向下取整。這補強前輪「插值候選」；**未執行或模擬原 SO，不是 native 逐位元等價證明**。
7. 【已驗證／修正缺口】原 **427 個 resource ID** 已全部從 xxhdpi 原始 ARSC 定位到 428 個保留 config 的 drawable 值。原 ARSC 的 10 個引用＋binary XML 的 682 個引用，與舊 692 次警告的 ID／次數多重集合完全一致。259 份 binary XML 包含這些引用，涵蓋遙控、設定、韌體更新及影像畫面。解碼後 XML 的文字搜尋曾回傳 0，原 binary 卻有真實引用，故不能用解碼 Java／XML 的缺失直接排除原程式行為。

## 密碼學與韌體的主要判斷

【已驗證】相機連線的 SHA-256 消費者輸入是 peer certificate encoded bytes，輸出供指紋比對。Lottie／Glide 關聯鏈處理快取 key，Google／Adobe 的若干雜湊處理 SDK 識別／授權資料。`h6/h.j` 的 Base64／ASCII 篩選／header 組合是編碼，不是加密；嵌入值沒有解碼、使用或公開。

【已驗證】`libavformat` 有實際 TLS 與壓縮串流消費者，因此本輪不只列出 `libcrypto` 的函式名稱。但目前沒有把相機更新檔的 bytes 接到這些消費者，也沒有恢復實際協商的 cipher／key／IV。`libcrypto.so`／`libssl.so` 各自 SONAME 是 `.so.1.1`，不能僅憑檔名差異判定相依庫缺失。

【尚未確認】本輪**沒有建立新的可驗證韌體解密／驗簽鏈**。新增的定點範圍包括五個 R8 case、Retrofit Proxy 的 Object／default／一般 service 分支、原 243 候選、69 個補充位置、70 個韌體入口種子的 depth≤8 呼叫參照圖、選定 Native 消費者。圖中的 2,526 個方法、7 個反射候選及 43 個轉換 API 參照是語法可達線索，沒有被當作韌體 bytes 污點證明。147 個未解目標、介面分派、外部模組及計算式註冊仍在邊界外。

## 哪些舊結論改變

- **補強**：LUT 原先只有插值候選；現在有六區域數學模型及原指令限制。Ghidra C 的整數 cast 不能取代 `FCVTMS` 的 floor 語義。
- **修正**：「427 個引用仍找不到原件」已解除為 ID／值／原引用可對照；完整 UI／Android configuration 行為仍未完成。舊警告原稿與所有原件保留。
- **修正範圍**：243 不是所有動態機制；現在明列 69 個額外位置。分類 100% 不代表語義 100%。
- **維持**：214 JNI＝197 靜態符號＋15 已核靜態註冊路徑＋2 未解；42 次 JADX error＝24 個不同方法。其餘 23 項已排序，沒有改寫成已恢復。
- **維持**：Android 更新的已核下載／ZIP／短讀／分片／HTTP body 模型不等同機身驗簽或安裝通過。全 App 仍可分析，不能說只剩相機端；要回答機身 UPD 認證／解碼則確實仍缺專有處理程式。

## 交付入口

- [密碼學／編碼資料流](CRYPTO_AND_ENCODING_MAP.md)、[動態呼叫與韌體補查](DYNAMIC_AND_FIRMWARE.md)
- [ARM64 與 LUT](ARM64_ANALYSIS.md)、[JNI／資源／23 方法缺口](PRIORITY_GAPS.md)
- [逐庫覆蓋](NATIVE_COVERAGE.md)、[E／G 準備](EG_PREPARATION.md)
- [原始輸入完整 SHA](INPUT_MANIFEST.md)、[程式位址索引](EVIDENCE_INDEX.md)、[重現](REPRODUCE.md)、[驗證結果](results/validation.json)

公開的是自寫工具、必要精簡指令證據與結構 metadata。原 APK／DEX／SO／固件、完整反編譯、合成測試檔及 Ghidra 專案留在忽略目錄。沒有修改原件、執行目標程式、連接相機、取得第三方憑證、破解金鑰或測試授權繞過。
