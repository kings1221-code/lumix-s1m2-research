# F：動態分派、反射與韌體補查

主要輸入兩份 DEX，完整 SHA 見 INPUT_MANIFEST。`dynamic_classification.json` 列出每個原候選、Caller、CU、API、分類、參數事實及未知；原始 invoke／字串 ID operands 見 selected_dex_evidence。沒有從名稱或單一 SDK 的 callee 推論全部入口。

## 243 個原候選的分類與分母

| 分類（部分仍是候選語義） | 位置 |
|---|---:|
| framework／混淆反射待解 | 111 |
| Google SDK | 39 |
| HTTP／TLS platform compatibility 候選 | 23 |
| Adobe notification compatibility | 17 |
| serialization reflection | 14 |
| TLS provider compatibility 候選 | 12 |
| Google 外部模組／security provider | 10 |
| ONNX native loader | 5 |
| App OS／Harmony compatibility | 4 |
| 影像／媒體 native bootstrap | 4 |
| App native bootstrap | 3 |
| App Room implementation loading | 1 |

243／243 已歸類只是清單覆蓋。CFG 以 const／move／class／forName／getMethod 等做交集資料流，加入 switch 及 exception edges，復原 95／243＝39.09% 的字面目標。另以原 DEX 陣列及迴圈證明一個 FFmpeg loadLibrary site 的有限 7 庫集合，合計 **96／243＝39.51%**；147 個未精確解決。四個自製 CFG 控制檢查合流衝突、相同常數、filled-new-array 只讀參數及 handler 的未改變 selector。

FFmpeg 的原 CU `0x0e` 建立 `[crypto, ssl, avutil, swscale, avcodec, avformat, ffmpeg_mediametadataretriever_jni]`，`0x1a` 載入，迴圈後 `0x20` 呼叫 native_init。宣告可達／有限集合不等於每次都載入成功。

【合理推論】AppDatabase.p 的 CU `0x18` class literal 進入 D1/Q constructor，`0x138` 讀 builder Class field，再做 package／canonicalName／`_Impl` 組合，`0x19a` forName。候選 AppDatabase_Impl 確實在 DEX；但 mutable field 的跨方法不變性尚未形式核完，**不計入 exact-resolution 數**。

## 舊索引沒有涵蓋的動態機制

另查出 69 個 Constructor.newInstance、Class.newInstance、Proxy.newProxyInstance、MethodHandle 等位置，完整保存在 firmware_dynamic_scope。它們與 243 分開統計，本輪沒有假裝全部已解。

【已驗證】Retrofit factory `Loa/v0.b` CU `0x8a` 建立 Proxy；handler `Loa/t0.invoke` 對 Object-declared 方法才走 CU `0x08` Method.invoke，default method 走建構子／MethodHandle 相容分支，一般 service 走 CU `0x47` `v0.c(Method)` → CU `0x4b` `w0.a(arguments)`。普通 firmware API 不能因這個 generic handler 存在，就被當成另一個 Native 解碼入口。原 HTTP body／converter 證據沿用前階段，沒有宣稱所有 adapter／interceptor 都已還原。

## R8 共用 Callable：五個 caller 分開處理

`g5/k.call` 的 packed-switch 在 CU `0x05`；以 constructor 的 selector 值與實際 case CFG 分配 callees。

| caller | selector | case CU | 本輪核實的區別 |
|---|---:|---:|---|
| EditActivity.O0 | 0 | 0x23e | 不套用 selector 1 的 native merge |
| EditActivity.E0(Uri) | 1 | 0xe7 | 條件路徑到 mergeCubeFiles，前輪鏈補強 |
| h5/l.b | 2 | 0xc8 | GalleryInfoEntity.getFileRating（0xda）→ writeVideoRatingJni（0xde） |
| LottieAnimationView.setAnimation | 3 | 0x9a | Lottie case，不套用 LUT native callee |
| z3/l.apply | 4 | 0x08（default） | 另一個 case，不套用其他 caller |

selector 2 的 Java capture path String 與 gallery rating int，經 `libllc.so` ELF VA `0x160c8` 的 GetStringUTFChars → writeVideoRating → ReleaseStringUTFChars，保持 int 回傳。這是**新確認的 caller／case 關係**，native wrapper 是沿用的既有恢復，不重計為新反編譯。下游 writer 的完整格式與所有錯誤路徑尚未新增恢復。

## 本輪韌體陰性結果的確切範圍

- 70 個含 Firmware 宣告／firmware annotation 的入口種子，依原 explicit invoke graph 做 depth≤8 查詢；2,526 個已定義方法、7 個原反射候選、43 個指定轉換 API 參照命中保留完整路徑。
- 圖不解析所有 virtual／interface／class initializer／reflection；因此只稱「呼叫參照可達」，不稱韌體 byte[] 污點分析已完成。
- 五個 R8 case、相機與第三方 native bootstrap、App Harmony／Room、Retrofit 代理、選定 Java／Native 轉換已定點核查。沒有發現能把原更新檔 bytes 交到新的 Cipher／JNI 解碼者的可驗證連線。
- 18 庫的原 symbol／relocation、指定 import BL，及兩個未決 JNI 的精確字串／指標候選掃描皆有實際實現與範圍；計算式與外部註冊未排除。

【尚未確認】以上結果是**沒有新建起韌體解密／驗簽鏈**，不是「全 App 已證明不存在」。147 個未解目標、69 個補充位置未全部恢復、SDK callback／provider 與機身程式缺口都保留。已核的下載／ZIP 選檔／單次 read／分片／ACK 模型不因本輪改為驗簽成功。
