# B：DEX／Java／Kotlin 與非同步還原

【已驗證】14,812 class、48,914 field、76,901 方法定義、48,522 不同 invoke target、349,415 invoke site。前者 class／field 是本輪補充，方法／呼叫資料沿用第一階段相同 SHA 的原指令索引；沒有重新全量 JADX。

完整描述子、flags、superclass／interfaces、field 類型、source_file metadata、方法及呼叫位置見 [dex_structure.json.gz](results/dex_structure.json.gz)。欄位 encoded_value_type 是編碼型別，沒有公開原始常數。字串另有 73,540 個 ID／DEX data offset／MUTF-8 raw SHA，[dex_strings.json.gz](results/dex_strings.json.gz)不公開原字串值。依賴圖是原始 invoke target，不是所有 virtual/interface dispatch 已解析。[package graph](results/package_graph.json.gz)。

`scripts/query.py --method 'mergeCubeFiles'` 可不依賴 APK 查詢 caller／callee；本機 `.research-local/full_reverse/knowledge.sqlite` 另有 methods／calls 索引。原始 ID／位址不改名；描述性別名及證據見 [semantic_aliases](results/semantic_aliases.json)。

## 非同步與混淆

【已驗證】680 個指定非同步呼叫位置、243 個 reflection／load 候選保存在 [dispatch_sites](results/dispatch_sites.json.gz)。模式只涵蓋列明 Executor／Handler／Thread／Task／Continuation／LiveData API，**不能稱所有 Rx／coroutine／listener 都已對上**。完整類別 interfaces 及 invokes 可用於後續繼續。

【已驗證】`g5/k` 是多 case 合成 Callable；constructor 將 selector 保存 q。`EditActivity.E0(Uri)` CU `0x2` 定 v2=1，CU `0x1ad` 把此 selector 傳入 constructor；中間無對 v2 的覆寫。`g5/k.call` 的 packed-switch CU `0x5` 將 key=1 指向 `0xe7`，這個 case 在 `0x213` 調用 mergeCubeFiles；成功回傳 0 時採用輸出路徑。其他建構者 selector=0／2／3／4 的路徑包含 Edit、gallery／Lottie 等不同內容，不能從共享 class 名稱把所有方法關係混在一起。[原 DEX 指令／offset](results/callable_case_evidence.json)。這是條件路徑，未宣稱每次 E0 都會合成 LUT。

## 24 個失敗方法的持續語義進度

【已驗證】42 錯誤事件、24 個不同方法及先前結構 CFG 維持不變。[逐方法狀態](results/failed_method_progress.json)保存每個 descriptor／DEX／code_item；沒有將 CFG 通過冒稱高階程式已恢復。

本輪新補 `Ll0/h;->D(BufferedInputStream,BufferedOutputStream)`：classes.dex code_item `0x49c810`，199 CU。它讀出 chunk length/type，根據實際類型進入下列資料路徑，而不是只憑常數命名用途：

- CU `0x4a`／`0x4e` 讀 length／type；IHDR 分支複製原 chunk，再按已保存狀態呼叫 L／M。
- CU `0x7e` 呼叫 L 寫出 EXIF chunk，CU `0x83` 跳過舊內容與 CRC。
- CU `0x95` readFully iTXt prefix、`0x9c` Arrays.equals；匹配特定 XMP prefix 時呼叫 M／跳過舊 chunk，不匹配則保留 prefix 和其餘內容。
- CU `0x46` 在待處理狀態清除後，呼叫 stream copy helper 複製剩餘資料。

L／M 的資料來源與 writer 顯示 CRC32 是 PNG metadata chunk 的 CRC。M 的 prefix 從同 class `<clinit>` 的實際字串 `XML:com.adobe.xmp` 加五個 NUL 建立；不是韌體 hash。合成控制以 22-byte prefix＋16-byte 自製 payload 得 CRC32 `7d619848`，分段更新與接合資料計算一致。

【已驗證】PNG D 的 199 CU 指令流以及 Google Task onComplete 的原始 opcode 次序，與官方 Apktool 所帶 Baksmali 3.0.9-dev 選定輸出相符。[Smali cross-check](results/smali_crosscheck.json)、[原 DEX 關鍵 operands／branches／raw bytes](results/semantic_dex_evidence.json)。完整 Java／Smali 留本機。

【尚未確認】D 的全部異常／截斷輸入語義、完整 EXIF／XMP round-trip 與全部狀態組合；其餘 23 個方法的高階恢復尚未新增完成，包括 RemoteShootingActivity.Y0 的 9,050 CU、MainActivity.a0、v.Q LUT parser、JPEG parser 等。沒有因 Java stub 的 UnsupportedOperationException 就斷言原程式會直接丟出該例外。
