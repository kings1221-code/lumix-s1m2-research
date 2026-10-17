# Native 分層覆蓋

【已驗證】18 庫有相同摘要的 symbol／ELF 盤點；累計 65 個不同選定函式有反組譯證據。本輪對 13 個函式另匯出工具 CFG，並回核 1752 指令列；12 指令 helper 窗口另外計，不冒充新的完整函式。357 個 PLT／2428 個 BL 是指定 import 的線性位置盤點，不算 2428 個函式語義。

| SO | dynsym 清單項（含 undefined） | 選定反組譯函式（累計） | 本輪明確工具 CFG | 有範圍模型控制 | 完整函式語義驗收 |
|---|---:|---:|---:|---|---:|
| libavcodec.so | 485 | 0 | 0 | 尚無 | 0 |
| libavformat.so | 583 | 4 | 4 | 尚無 | 0 |
| libavutil.so | 690 | 0 | 0 | 尚無 | 0 |
| libc++_shared.so | 2498 | 0 | 0 | 尚無 | 0 |
| libcrypto.so | 4524 | 0 | 0 | 尚無 | 0 |
| libcube_merge.so | 19 | 9 | 9 | 3 個 cube 有限模型／輸出 | 0 |
| libde265.so | 2933 | 0 | 0 | 尚無 | 0 |
| libffmpeg_mediametadataretriever_jni.so | 171 | 19 | 0 | 尚無 | 0 |
| libheif.so | 414 | 0 | 0 | 尚無 | 0 |
| libllc.so | 163 | 31 | 0 | 尚無 | 0 |
| libonnxruntime.so | 211 | 0 | 0 | 尚無 | 0 |
| libonnxruntime4j_jni.so | 198 | 1 | 0 | 尚無 | 0 |
| libssl.so | 953 | 0 | 0 | 尚無 | 0 |
| libswscale.so | 76 | 0 | 0 | 尚無 | 0 |
| libtechorfilter.so | 12086 | 0 | 0 | 尚無 | 0 |
| libyuv-decoder.so | 11 | 0 | 0 | 尚無 | 0 |
| libyuv.so | 769 | 0 | 0 | 尚無 | 0 |
| libyuv_android.so | 552 | 1 | 0 | 尚無 | 0 |

**不計算假的總語義百分比。** Dynsym 不含所有內部函式；Ghidra 函式識別、CFG export、C 產生、原指令回核與合成數學控制的分母不同。表內 0 是本輪沒有宣稱完整函式語義驗收，不表示函式沒有部分資料流成果。每個選定地址、SHA 與各層狀態見 results/native_coverage.json。
