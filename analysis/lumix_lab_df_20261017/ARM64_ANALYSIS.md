# ARM64：實際串流消費者與 LUT 語義控制

全部地址為各自 ELF VA，**不是檔案偏移或相機地址**。原 bytes 依對應 ELF 的 PT_LOAD 映射，不能加一個通用常數。完整 SHA 見 INPUT_MANIFEST；每個選定函式的 Caller／Callee／CFG／指令摘要見 `native_evidence.json`，完整 Ghidra C／反組譯僅存本機。

## 新增 libavformat 消費者

輸入 `libavformat.so` SHA-256：`4d364b5e2855c8e828eb02474c3cec47b8801f88a59c8625dc64a260604eaa79`。

| ELF VA | 有實際程式碼支持的動作 | 仍未知 |
|---|---|---|
| 0x1354fc | context+0x10 的 private 結構；client/server flag +0x28 選 TLS method；SSL_CTX 存 +0x118，SSL object 存 +0x120；設定 BIO callbacks；條件讀 CA／certificate／key file options；SSL_connect／accept，失敗 cleanup | 實際 URL／option、key／certificate 檔案與協商 cipher／IV，不讀取任何真實私密檔案 |
| 0x135754 | caller buffer／length → SSL_read → 結果／錯誤翻譯 | 哪個 App invocation 實際選到該 transport |
| 0x135794 | caller buffer／length → SSL_write → 結果／錯誤翻譯 | 沒有固件 byte[] 來源連線證據 |
| 0xb8aa4 | 條件壓縮狀態；read helper／0x40000 暫存；設定 stream input／output pointers 與 remaining length；inflate(stream,2)；回傳 request length−remaining | 所有 reconnect／protocol／錯誤狀態、實際 firmware 使用均未建立 |

【已驗證】`0x135a84` 的 12 指令窗口先從 context+0x10 取 private pointer，最後把 +0x120 的 SSL object 放入 x0，保留 buffer／length registers。**它不是純 getter**：還把父 context flags+0x20 的 bit 0x8 同步至底層 context(+0x110) 的 flags+0x20。原始 bytes／反組譯逐列保留，避免依 Ghidra 的多值回傳暫型別推論參數遺失。

【已驗證】四函式有實際 SSL／inflate 呼叫和緩衝區消費；不只是有 libcrypto exports。但這不證明相機 firmware API 走它們；Android 相機 TLS 指紋流程仍是不同的 Java 消費者。

## 全庫 symbol 與呼叫層級

18 庫沿用相同摘要的 dynsym，再補查指定 imports 的真實 RELA JUMP_SLOT → PLT ADRP/LDR GOT → BL immediate。357 個選定 PLT、2,428 個 BL 位址另以 Capstone 獨立解碼，保留每個原始檔案偏移／bytes。這是線性分支位置盤點，**不是全部函式 CFG，也不代表這些路徑於 App 本次會執行**。

`libcrypto.so` 與 `libssl.so` 的 SONAME 為 `libcrypto.so.1.1`／`libssl.so.1.1`；Java FFmpeg 的原 loader 有先載入 crypto／ssl 的有限集合。不因檔名／DT_NEEDED 字面差異而報告缺庫。尚未在 Android loader 實機環境驗證載入成功。

## libcube_merge：由候選補強為有範圍的數學模型

輸入 SHA-256：`91c35f56413f0e6fd8108000104a4270b6beee64121bfd954ada56e510c03d2f`。前輪九個函式維持相同 VA；本輪不重計為九個新函式。

- `0x5714`：n 與資料指標；資料索引是 `(b*n*n+g*n+r)*24`，三個 double 一組。CU／VA 證據顯示 R 最快、G 次之、B 最慢。
- `0x5764..0x5770`：`SCVTF s1,w8`、`FDIV s0,s0,s1`、`FCVT d0,s0`，間距為 float32 的 `1/(n-1)` 再 promote，不能用理想 double 間距取代。
- `0x5788` 等位置為 `FCVTMS`，是 floor，不能單照 C 的 `(int)` 假設截向零。cell index 夾至 0..n−2，但輸入座標／fraction 沒有因此被夾成 0..1。
- 六種 fraction 排序選擇四個角點，權重為 `1−max, max−mid, mid−min, min`。自寫六分支版本與獨立排序／角點版本做對照，支持四面體插值語義。
- `0x4e60`：第一份 grid 的各 triplet 送入第二份 evaluator，寫第三份結構；前輪第三參數 x2 證據保持不變。
- `0x4fdc`：`LUT_3D_SIZE %d\n\n`，逐 triplet `%.7f %.7f %.7f\n`，有結果／錯誤清理分支。不是二進位加密容器。

【已驗證／自寫模型】1044 個 finite 案例涵蓋 n=2／3／4／17、六種嚴格排序、tie、端點及部分外插；六分支與排序公式最大差 0。identity grid 的最大誤差約 **3.5763e−8**，反映單精度間距。另用 3³ 的 A-grid channel permutation 與 2³ B-grid affine transform 核對組合，產生 27 行七位小數輸出並重新解析。

【尚未確認】這不是原 native 執行或模擬結果，也未證明 fused operation／所有 rounding 的逐位元一致。NaN／Inf、n<2、整數溢位、超額／畸形 body 行、locale、所有 allocation／I/O 失敗與記憶體安全行為未完成。`0x52dc`／`0x54c8` 的所有 parser 分支仍列缺口，不把合成正常輸入通過稱為整個 parser 安全。

## JNI 新 caller 關係

`libllc.so` SHA-256：`7433d705215bb92e7a87b9005277127e5851c7a4638ca8f6a3db17d2a00927df`。selector 2 以 gallery rating int 與捕捉的 path String 呼叫 `writeVideoRatingJni`（ELF 0x160c8）。原 wrapper 在 JNIEnv+0x548 取字串，呼叫 writeVideoRating，再由 +0x550 釋放，保留 int 回傳。這補強原 JNI 對照的上游 Caller，不新增已恢復下游 writer 的宣稱。詳見 DYNAMIC_AND_FIRMWARE 與 jni_gap_audit。

本輪 13 個函式共 1,752 指令列回核原件，另有上述 12 指令窗口；與前輪累計 **65 個不同選定函式**。逐庫 symbol／反組譯／工具 CFG／模型層級分列 NATIVE_COVERAGE，沒有總語義百分比。
