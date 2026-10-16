# C：原生函式、資料結構及跨庫 LUT 處理

所有 18 個原 ELF Header／sections／segments／DT_NEEDED／dynsym／init-array metadata 見 [elf_structure.json.gz](results/elf_structure.json.gz)，完整輸入 SHA 見 INPUT_MANIFEST。全部為實際讀到的 ELF64 little-endian EM_AARCH64；這是 Android SO 的架構，不移植為相機固件架構。

本輪使用 Ghidra 12.1.4，AARCH64:LE:64:v8A；這批程式 Ghidra 地址 = ELF VA + `0x100000`，每條新採用指令依實際 PT_LOAD 對回原檔。**1,543 條比對通過**，完整 C 與指令留本機，精簡 metadata 見 [native_evidence.json](results/native_evidence.json)。自動分析／decompiler 警告保留在本機日誌，不因 exit=0 稱所有 C 正確。

| SO | SHA-256 |
|---|---|
| libllc.so | `7433d705215bb92e7a87b9005277127e5851c7a4638ca8f6a3db17d2a00927df` |
| libcube_merge.so | `91c35f56413f0e6fd8108000104a4270b6beee64121bfd954ada56e510c03d2f` |

## 由 Java 參數到檔案輸出

【已驗證】EditActivity.E0(Uri) 的條件背景工作建立 `g5/k(selector=1,...)`；該 case 的 merge 呼叫及 0 回傳時的輸出路徑採用有原 DEX operands／branch 證據。共享 Callable 的其他 selector 不能等同此處行為。

`libllc.so:0x122ac` 依次從三個 Java String 經 JNIEnv `+0x548` 取得 UTF 字串指標，原樣交給 cube_merge_files，保留其 int 回傳值，再經 `+0x550` 釋放三個字串。此處檔案操作由下一個 native library 消費，不是僅以函式名稱推定讀檔。

| libcube_merge ELF VA | 真實消費者／輸出及證據範圍 |
|---|---|
| `0x51d0 cube_merge_files` | 讀第一、第二個路徑，呼叫網格合成，將第三路徑與輸出結構交給 writer；全部三個結構清理。失敗回傳 -1／-2／-3，正常路徑初始 0。未作 native runtime 測試。 |
| `0x4dac` | fopen 讀取 → `0x52dc` 頭部 → `0x54c8` body → fclose，回傳供上層判斷。 |
| `0x52dc` | 逐行 token，實際以 sscanf／strncmp 消費 LUT_3D_SIZE，交給 allocator；Ghidra 對 libc buffer 型別有失真，未把全部 C 原型當作精確格式規格。 |
| `0x54c8` | n³ 筆三個 double 的 sscanf 消費與 0x18 stride；EOF／parse result 影響回傳。完整 malformed-input／上界行為未驗收，不據此宣稱安全解析。 |
| `0x56b0` | 結構 +0 寫網格整數，+8 保存 calloc(n³,0x18) 指標；+4 區域／整個結構語義不額外猜測。 |
| `0x4e60` | 三重網格遍歷，取第一輸入 24-byte triplet，經第二輸入 evaluator，再寫第三輸出結構。 |
| `0x5714` | 由座標決定 cell／六種排序區域，讀 corner triplets 做加權並覆寫輸入 triplet。【合理推論】屬分區插值，候選四面體 LUT 插值；尚未完成獨立數學等價與邊界測試。 |
| `0x4fdc` | fopen 第三路徑 w，fprintf LUT_3D_SIZE 及 n³ 筆 `%.7f` triplets，失敗處理含 remove；沒有在本輪執行任何原生檔案寫入。 |
| `0x5198` | 清理結構 +8 指標；上層對三個結構均呼叫。 |

## Ghidra 遺失參數的修正

【與既有結果衝突】未修正 caller C 只顯示 `FUN_00104e60(&input1,&input2)`，看起來 output 沒被填入。原 ARM64 是：

```text
ELF 0x5258  sub x0,x29,#0x18
ELF 0x525c  sub x1,x29,#0x28
ELF 0x5260  add x2,sp,#0x38
ELF 0x5264  str x2,[sp,#0x10]
ELF 0x5268  bl  0x4e60
ELF 0x526c  ldr x1,[sp,#0x10]
ELF 0x5270  ldr x0,[sp,#0x20]
ELF 0x5274  bl  0x4fdc
```

【已驗證】第三參數是實際的輸出結構地址；callee 也消費第三指標。`FixNativePrototype.java` 僅對 Ghidra 分析資料套用 void＋三個 64-bit pointer 參數，`-readOnly` 重處理後產出 `FUN_00104e60(&local_28,&local_38,&local_48)`。這是有指令依據的型別修復，**沒有修補 SO、APK，也沒有把此最小指標型別當成完整 C++ 原碼**。

## 覆蓋及停止

本輪新讀到的 cube 專案識別 68 個函式／thunk 等項目，其中 9 個選定函式留有本輪 decompiler／指令記錄；分母不等於真實全部來源函式。libllc 選定兩項是對前階段資料的定點交叉核查，沒有重跑它的全面 auto-analysis。累計 61 個不同函式含第一階段，**不是 18 庫都完成語義分析**。libcrypto／libssl／libtechorfilter／codec 等大型庫目前多為 metadata／既有符號範圍，精確逐庫狀態見 COVERAGE。

splitYuv 緩衝區處理另見 JNI_NATIVE_MAP；未建立此處任何函式與韌體 payload 的實際資料鏈。更深插值等價、檔案錯誤邊界及其他庫後續分析保留待辦。
