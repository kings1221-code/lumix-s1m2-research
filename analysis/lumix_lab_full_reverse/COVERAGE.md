# COVERAGE：分母與證據層級

| 層級 | 已覆蓋 | 沒有表示 |
|---|---|---|
| 原始身分／容器 | 25 inputs；5 APK 的 4867 members 完整 hash／CRC | publisher 簽章新驗證或 runtime 成功 |
| DEX 結構 | 14812 class、48914 field、76901 method；349415 invoke；73540 string ID／hash | 全部方法語義／字串用途已懂 |
| 資源 | 5 binary manifest 的節點／指定 SDK 屬性；13886 ID；28 nav 節點 | 427 個 unresolved IDs 已合併，或全部 UI 能重建 |
| 動態／非同步 | 243 load/reflection 候選；680 指定 async sites；1 shared Callable case 有 operand 證據 | 反射／virtual／Rx／coroutine 全部解析 |
| 失敗方法 | 24 CFG 沿用；本輪 1 項新增部分語義；0 項宣稱完整高階恢復 | 42 個不同方法，或所有 Java stub 都是真實異常 |
| Native | 18 ELF 結構／符號相同輸入；累計 61 選定函式有 Ghidra 記錄 | 全部函式、struct 或原生庫已完整還原 |

## 逐庫範圍

| SO | 已定義 STT_FUNC dynsym 數 | 累計選定 Ghidra 函式 | 語義界線 |
|---|---:|---:|---|
| libavcodec.so | 167 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libavformat.so | 157 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libavutil.so | 587 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libc++_shared.so | 1583 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libcrypto.so | 4249 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libcube_merge.so | 2 | 9 | partial selected consumers only |
| libde265.so | 2029 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libffmpeg_mediametadataretriever_jni.so | 94 | 19 | partial selected consumers only |
| libheif.so | 271 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libllc.so | 70 | 31 | partial selected consumers only |
| libonnxruntime.so | 3 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libonnxruntime4j_jni.so | 181 | 1 | partial selected consumers only |
| libssl.so | 495 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libswscale.so | 31 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libtechorfilter.so | 9152 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libyuv-decoder.so | 3 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libyuv.so | 711 | 0 | ELF/symbol/dependency inventory only; function semantics pending |
| libyuv_android.so | 298 | 1 | partial selected consumers only |

**不以這兩欄相除作語義完成率**：dynsym 不含所有內部函式，Ghidra 的 identified functions 也包含 thunk／分析項目。libcube_merge 專案識別 68 項，本輪讀 9 個指定函式；libllc 專案識別 417 項，只作既有函式的定點核查。libcrypto 等大型庫多數內部仍未讀。新 1543 條指令逐條回原 ELF，不把重複核查的兩項 libllc 函式算新增。

D／E／F／G 全面展開：未開始，等待使用者審查。
