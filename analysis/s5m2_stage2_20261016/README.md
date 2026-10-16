# Panasonic LUMIX S5M2 韌體研究：第二階段驗證報告

日期：2026-10-16（Asia/Taipei）。分支：`codex/s5m2-stage2-20261016`。本輪完成保存核對、E1、E2、Android B 的必要核查，以及直接相關的 D 狀態補充；**沒有取得真正的機身 UPD 解碼器，E3 停在缺少實際處理程式的邊界**。使用者要求收尾後未增加搜尋範圍。

## 六個交付問題

1. **S5M2 格式哪些已核實？**【已驗證】V3.1／V3.7 完整 ZIP、BIN SHA-256、ZIP 成員 CRC、雙層 `UPD\0`、頭部字節、CRC32 覆蓋、54／58 個目錄項、92-byte 記錄、每項實際載荷範圍及摘要、連續性與末尾填充。兩版共 112 項與既有正確語料逐欄相符。這是格式交叉驗證，沒有把舊結果冒稱全新解碼成果。
2. **找到真正接收及解析 UPD 的機身程式嗎？**【尚未確認】沒有。在下列六份精確官方來源包、既有全包掃描及本輪指定函式覆核內，沒有建立現代 UPD 的實際接收／解析消費者鏈。**這不等於該機型不存在該程式，也不等於所有公開套件均已排除。**
3. **有可核的驗簽、解碼、解壓或載入函式嗎？**【已驗證】公開來源有 `do_unzip → gunzip → gzip_parse_header / zunzip → inflate` 及 `do_booti → booti_start → booti_setup / memmove / do_bootm_states` 等一般記憶體消費者。【尚未確認】它們與原始 UPD 的前級接收、認證、解碼及鏡像生產者之間仍未接上，不能稱為 UPD 解碼器或已驗證的實機載入鏈。
4. **Android 傳送末端還不清楚嗎？**【已驗證】已補選檔與路徑重組、短讀、分片序號／回應、取消與錯誤、Retrofit body 身分轉換、HTTP 緩衝區與 HTTP/1、HTTP/2 載荷傳遞。所追蹤的內容以 byte[] 複製進入傳輸層，沒有恢復新的韌體解密／驗簽程式。短讀與取消的實際時序、Android 平台 TLS 實作、機身收到後的處理仍不是本輪證明的範圍。
5. **具體缺什麼？** 最優先缺 **S5M2 機身實際承接 `firmware/send-prepare`、`firmware/send`、`firmware/abort-send` 的服務與其更新分派程式**，以及它呼叫的 UPD 認證／解碼實作。也缺其版本對應的啟動／服務配置、可讀執行檔／共享庫或其他處理器程式、部署 DTB／映像與分段映射。公開端點名稱與 BIN 目錄不能填補這個缺口。
6. **下一個最值得研究的元件？** 就是上述**實際接收服務到更新處理器的交接點**。目前不知道其真實檔名、函式名、位址或一定屬於哪個處理器；不為它虛構 `updater` 檔名。取得條件與驗收清單見下文。現階段停止大規模分析，等待審查。

## 保存及輸入身分

【已驗證】第一階段提交 `69333e24675fcdbe2f7d00481a3360af78a1ea9e` 與遠端分支一致。33 個公開交付檔、25 個原 APK／DEX／ARM64 SO 的完整摘要重核通過；未保存的第一階段研究正文或腳本沒有遺漏。完整反編譯原碼、DEX 指令轉儲及 Ghidra 專案仍保留於本機忽略目錄，不上傳。

【已驗證】由實際保存的 JADX 日誌核到 **42 次錯誤、24 個不同方法**；24 項最終 CFG 指令索引與 gzip 摘要吻合。這只表示結構 CFG 可恢復，不表示全部高階語義已恢復。第一階段 `jadx_failures.json` 的初期 `to_be_verified` 欄位不是最終驗收狀態，最終以 `failed_method_cfg_index.json` 為準。

【已驗證】從 214 項 JNI 對照逐列重算：197 項靜態符號對照、15 項有靜態註冊路徑、1 項有 C++ 改名實作但綁定不明、1 項在現有 18 庫中未解決。沒有把媒體 JNI 改稱韌體解碼器。

Fork／上游 main 在開始時均為 `8f625cfabb31e8a71177b86e2b63a69c686de5e8`。原個人研究分支未合併、重寫或刪除；本輪從第一階段建立新分支。既有未追蹤 `downloads/`、附件保留。原廠 APK／BIN／ZIP／SO 不加入 Git。

證據：[第一階段保存核查](results/stage1_preservation.json)、[本輪全部 35 項輸入身分與來源層級](results/inputs.json)、[工具環境](results/environment.json)。35 是路徑／容器成員身分數，包含相同內容的兩份 FreeRTOS 包，不代表 35 份獨立程式。

## E1：S5M2 V3.1／V3.7 實際結構

### 完整 SHA-256

| 輸入 | bytes | SHA-256 |
|---|---:|---|
| V3.1 ZIP | 186,598,983 | `2e3a5ce15e71079a3cba6acf412393fba30270389409bf637f8d285fef7b518a` |
| V3.1 BIN | 205,683,712 | `3ce8a371c2a3c088e573a5716ab92dd6a095a780b1d58420d4d6856ed75afd58` |
| V3.7 ZIP | 157,761,949 | `5e92c6adc967159369937c0313beefdfd9934ff365663b70ade4b906400f2774` |
| V3.7 BIN | 179,207,168 | `99180a1738d74d0d0062e146dd0f239f65cb5bca6b49a8d2a1a94a8018d93ffa` |

【已驗證】每個 ZIP 只有一個 BIN 成員，壓縮方法為 ZIP method 8，讀至 EOF 的成員 CRC 通過；本輪另核 ZIP local header、central directory 及 EOCD 偏移。[逐項機器證據](results/firmware_structure.json)列出所有大小、偏移、原始欄位 hex 與完整載荷 SHA。

V3.1 與歷史保存的[官方 URL 及完整 ZIP 摘要紀錄](../sources/lumix_sync_static/official_firmware_list/S5M2_full_inventory.json)相符；沒有新的發行者身分驗證。V3.7 符合本機 2026-10-15 官方 HTTP 下載紀錄，2026-10-16 的[官方版本頁](https://av.jpn.support.panasonic.com/support/dsc/download/ff/dl/s5m2.html)仍列同檔名。原始 HTTP 紀錄只在本機保存；公開清單排除 cookie。**這些都是來源／內容一致性證據，沒有完成機身韌體簽章驗證。**

### 位元組及範圍

| 位置／欄位 | 兩版實測／差異 | 語義界線 |
|---|---|---|
| `0x000..003` | `55 50 44 00` | 外頭 magic |
| `0x004`、`0x008`、`0x038` 的 LE u32 | 均為 `0x200` | `0x038` 作為本批載荷相對位移的基準已由全部範圍核對；revision 等名稱沿用研究命名，不證明消費者語義 |
| `0x00c..01b` | NUL 結尾 `MC8223` | 型號欄位字節；不據此決定全部 ISA／硬體 |
| `0x01c..02b` | 完整原始字節保存在 JSON | 未自行發明版本編碼 |
| `0x034` | `03 00 00 00` | 舊名 selector，演算法未知 |
| `0x03c` | V3.1 `00 7a 42 0c`；V3.7 `00 7a ae 0a` | LE 值分別等於 BIN 長度減 `0x200` |
| `0x040` | V3.1 `83 68 ee be`；V3.7 `4a d4 3e cf` | CRC32 分別 `beee6883`／`cf3ed44a`，覆蓋 `[0x200, EOF)` |
| `0x200..21f` | 32-byte 區域，原值見 JSON | 不當作密鑰 |
| `0x220..25f` | 64-byte 候選欄位，原值及 SHA 見 JSON | 不是已證實簽章或解密材料 |
| `0x260..29f` | 兩版皆 64 bytes 全零 | 僅為原始內容事實 |
| `0x2a0` | 第二處 `UPD\0` | 內頭 |
| `0x2e8` | `36 00 00 00`／`3a 00 00 00` | 54／58 項 |
| `0x2ec` 起 | 每項 92 bytes | 本輪在 S5M2 輸入逐項驗證，不以 S1M2 的格式代替 |
| 目錄結束到資料起點 | V3.1 `[0x1654,0x1800)` 428 bytes；V3.7 `[0x17c4,0x1800)` 60 bytes；皆全零 | 載荷從 `0x1800` 開始 |

目錄記錄：`+0x00` 名稱 12 bytes、`+0x0c` 相對位移、`+0x10` 大小、`+0x14` 中性名稱 destination、`+0x18` flags、`+0x1c` 32-byte 摘要候選、`+0x3c` 16-byte 候選、`+0x4c` 16 bytes。所有實際資料起點使用 **`0x200 + entry.relative_offset`**；沒有把 destination 當作檔案位移、RAM 地址或 flash 地址。保留目錄索引與重名出現序。

【已驗證】V3.1 有 14 項 flags=2、40 項 flags=3；V3.7 為 15／43。flags=2 的 raw 摘要與目錄欄位相符；flags=3 raw 摘要不相符。本批末 16-byte 欄位皆零。這不證明 flags=3 使用特定加密、摘要對象或 IV 語義。

【已驗證】最後一項分別是 `[53]`／`[57] mbr_dummy_d`，兩者均 **131,072 bytes 全 FF**，raw SHA 為 `b5a41c3758763bbec72769fab4a2533bf2db0b6312d93d25a695f9e4b9e02260`；結束剛好等於 EOF。末尾 512 bytes 位於這個全 FF 項內，**沒有獨立 RSA-4096 簽章尾段的字節證據**。不把舊 S5 報告的標籤移植到這兩份 S5M2。

### 兩版目錄／內容差異

【已驗證】以「名稱＋同名出現序」配對，保留左右索引，54 項共同、無移除、V3.7 新增 4 項：`[6] compress_pr`、`[49] grid_data`、`[55] hm_d_nw_6th`、`[56] hm_d_nw_7th`。這是配對規則，不自動證明模組語義等價。

共同 54 項中：4 項大小改變、0 項 flags 改變、48 項 destination 改變、17 項目錄摘要欄位改變、40 項前 16-byte 尾欄位改變、40 項完整 raw 載荷 SHA 改變。17／40 不是函式或明文修改數。

新增、共同、逐項左右索引及各欄是否相同全部保存在 [comparison](results/firmware_structure.json)。本輪沒有重跑舊十版本、14 組與四方全面差分；原始歷史仍由 `0e9e45c54a6cadf9095a612fe03d34839ef638ff` 的完整語料保存。

## E2／E3：官方來源與消費者停止點

官方來源為 [DC-S5M2 Ver1](https://ospo.panasonic.com/oss/dsc/DC-S5M2.html) 及 [DC-S5M2 Ver2](https://ospo.panasonic.com/oss/dsc/DC-S5M2%28Ver2%29.html)。本輪保存四份官方頁面快照與摘要，六份包均與精確歷史 SHA 相符，且 URL 仍出現在官方頁連結中。詳見 [來源頁證據](results/official_pages.json)、[OSS 邊界及完整函式索引](results/oss_boundary.json)。

| 官方頁／包 | bytes | SHA-256 |
|---|---:|---|
| Ver1 U-Boot | 18,797,603 | `e7d301fb8b2cc509d7d5d42b53c13a61e6c21d5792804b314927b2f6cd2b40d3` |
| Ver2 U-Boot | 18,794,907 | `c27cf53af6d8e3a18af0455fe7841c8db955bb58c5943ef94a3a6632439ad692` |
| Ver1 Linux | 165,739,116 | `617c2712db38aed13cd5b6e96890d759d1b215ad20768dddd716b8ceaebc7811` |
| Ver2 Linux | 165,783,865 | `2468af4cfb8fa6e22cca5d2660ea270e14e1cceaa1c63359756aab396b791d67` |
| Ver1／Ver2 FreeRTOS（兩份相同） | 各 68,566,076 | `2078beb8ec3714b4a0a7e9d51456674eac5d0c7ee1d922f88e59493e28c43f97` |

### MC8223／MC8223X 的真實差異與不可跨推論事項

【已驗證】Ver1 包板級標為 MC8223，Ver2 標為 MC8223X。沿用且核對身分的歷史完整清單：U-Boot 兩包各 15,224 個常規檔案，15,221 個相同路徑內容相同、3 個名稱移除／3 個新增；Linux 各 61,995 個，61,990 個相同、5 個移除／5 個新增。14 個指定 C 函式在兩版同路徑檔案內容相同。FreeRTOS 兩個整包摘要、16,274 個常規檔案都相同。

【已驗證】本輪對已讀的 5 對更名板級檔做位元組比較：U-Boot defconfig／DTS、Linux defconfig／DTS／rtos.h，均在精確替換 `MC8223`→`MC8223X` 後完全相同。具體差在 DEVICE_TREE、model、compatible、include 檔名及註解；這 5 對沒有另外的數值差異。[逐行差異及完整檔案摘要](results/oss_selected_diff.json)。其他 3 對（U-Boot dtsi、Linux dtsi／gpio.h）本輪只沿用完整清單的大小及摘要，沒有宣稱新做了配對內容語義覆核。

**不能由此推論**：官方網頁放錯檔、MC8223X 與 MC8223 完全相同、兩種來源標籤分別就是 V3.1／V3.7 的構建、實機採用這份最終 .config／DTB、專有更新器相同、BIN destination 是上述來源地址、全部處理器皆為 ARM64，或存在可直接跨機型移植的解碼器。

### 已讀程式碼、呼叫與阻塞位置

以下行號是**原始 Ver1 包內檔案**，Ver2 同路徑 C 檔字節相同。每個檔案完整 SHA、函式 byte span／SHA、原始行號與詞法呼叫索引在 [oss_boundary.json](results/oss_boundary.json)；詞法呼叫者不是已連結或執行過的 call graph。

| 程式碼／函式 | 直接可核對的輸入與動作 | 尚缺／不能升級為的結論 |
|---|---|---|
| `u-boot/configs/pvc04v_MC8223_defconfig:43` | 配置 `unzip 0x400200000 0x403700000; booti 0x403700000 - 0x401290000` | 這些 RAM 內容由誰讀取、驗證、解碼及放置；不是機身執行紀錄 |
| `u-boot/cmd/unzip.c:10 do_unzip` | 命令列 src／dst 指標 → `gunzip(dst, dst_len, src, &src_len)` | 沒有從原始 UPD／更新端點到此函式的鏈 |
| `u-boot/lib/gunzip.c:44 gzip_parse_header`、`:72 gunzip`、`:275 zunzip` | gzip 頭部與記憶體輸入 → inflate → 目的緩衝區 | 解壓程式存在，不等於已找到韌體加密解碼器或驗簽者 |
| `u-boot/cmd/booti.c:63 do_booti`→`:19 booti_start` | 讀取已存在的 Image 地址，呼叫 booti_setup、必要時 memmove，再進入 bootm 狀態 | 缺實際 Image／DTB、前級生產者與部署映射 |
| `board/socionext/sc2006a-evb/sc2006a-evb.c:6 board_init` | return 0 空樁 | 不能當作更新初始化器 |
| `arch/arm/mach-milbeaut/milbeaut.c:65 dram_init` | FDT 記憶體設定助手 | 沒有原始 UPD 的讀取／認證鏈 |
| `linux-4.19.124/drivers/mtd/devices/slram.c:128 register_device`→`:106 slram_read` | memremap 既有記憶體；memcpy 回讀 | 缺鏡像寫入者；不是讀 BIN 並解碼的函式 |
| `linux-4.19.124/fs/ipcufs.c:1084 ipcufs_readpage`→`:473 ipcufs_transfer` | IFSA_READPAGE、檔案 handle／offset／共享頁 → IPCU 訊息；取回頁面 | 缺遠端檔案服務動作分派者及實際更新處理者；不能把 IFSA_READPAGE 稱為 UPD 處理 |
| `linux-4.19.124/init/main.c:1335 kernel_init`、`:1389 kernel_init_freeable` | rdinit／init 候選檢查及啟動 | 缺部署 rootfs、啟動腳本與服務配置；不能僅憑 rdinit 字串認定機身 updater |

MC8223 Linux DTS 的 bootargs 包含 `rdinit=/sbin/finit root=/dev/mtdblock0` 及兩段 slram 配置。來源配置確實存在，**未驗證為 V3.1／V3.7 的實際部署地址與檔案系統映射**。本來源 Makefile 只列參數化 DTB 名稱；沒有套用 S1M2 的 `-shell.dtb` 缺口論證。

### 搜尋的完整範圍與未覆蓋處

【歷史檢查、輸入身分本輪重核】`3362325de9e36e067f1826575f0fffde24ed98fd` 中的實際全包掃描讀取六包的**全部常規檔案完整字節**；本輪不重跑。每版 U-Boot 15,224 檔、Linux 61,995 檔、FreeRTOS 16,274 檔。精確 regex、byte offset／上下文及逐項清單保存在該提交 `analysis/s5m2_boot_consumer_audit_20261014/results_checked/source_audit.json`，本輪以摘要鎖定。[本輪覆核索引](results/oss_boundary.json)保留輸入、範圍及模式。

模式包括大小寫不敏感的 `\bUPD\b|UPD\\(?:0|x00)|55504400`、指定現代欄位名、`loader1|eep_act_a|postboot1_r|compress_pr` 獨立詞與列明 RAM 常數；FreeRTOS 另查列明 vendor／platform 字樣。**不是零命中**：每版 U-Boot 65 個 UPD 模式命中、Linux 37、FreeRTOS 3；包括其他板卡、Intel FSP／UPD、構建／網路字樣及 STM32 CHM 原始字節等，未建立 S5M2 更新消費者關係。現代欄位名模式無命中，只支持該組模式的陰性。

【本輪直接覆核】六包 SHA、兩個版本各 14 個 C 函式的原始 byte span、選定板級檔，以及已列的 5 對來源文字差異。沒有把舊掃描標成新跑；沒有用關鍵字陰性替代實際消費者核驗。

**仍未覆蓋**：官方其餘套件與配方／完整使用者態；tar 非普通成員指向內容；包內 ZIP／CHM 等巢狀文件的解開內容；其他名稱／編碼／間接計算；未取得的專有服務、其他處理器／安全模組程式；部署後修改、真實 flash／RAM／DTB／rootfs。未對固件內不透明載荷宣稱已恢復指令、完成驗簽或找遍全機。

## B／D：Android 末端結果

詳見 [Android 定點技術報告](ANDROID.md)、[81 方法位置／呼叫索引](results/android_method_index.json)、[原始 DEX 指令及 raw bytes](results/android_instruction_evidence.json)、[合成控制結果](results/synthetic_controls.json)。所有新 DEX 結論使用 Lab 3.1.0 versionCode 22 的原始兩個 DEX；完整 SHA 與指令檔案位置均在索引中。

【已驗證】首個一般檔案按 ZIP 枚舉衍生的列表順序選擇，之後取 basename 再 resolve 到解壓根；不是保留原完整相對路徑。沒有在該選擇區核對副檔名、UPD magic 或內容摘要。官方這兩份 ZIP 都只有根目錄 BIN，沒有這類巢狀路徑差異。

【已驗證】`x0` 的單次 `skip/read` 回傳值都被忽略；配置長度而非實讀長度交給 request body。自製 21-byte 檔以 8-byte 分塊可正常重組；假設已記錄長度 21、實際檔縮成 17 bytes，最後一片配置 5 bytes、只讀 1 byte、body 為 `11 00 00 00 00`，宣告長度仍 5。這是自行重建程式在主機 JDK 的合成控制，**不是執行 APK、Android 實測或機身接受證據**。

【已驗證】ACK 控制後續分片；`DETAIL_TRANSFERRED` 只表示客戶端走到最後成功回應分支。取消回應成功／失敗均可進同一清理 callback，不代表機身 abort 已確認。只補 BLE 特徵 `16726c35-52ef-4d00-868d-099549a90d9b` 與更新 operation state 的關係、Wi-Fi 前置門檻、現有 token／憑證／HTTPS 載荷路徑；沒有重新展開無關 GATT 或 API。

## 繼續找真正解碼器所需的證據

| 優先順序／缺失元件 | 需要何種原始證據 | 有了之後要核對什麼 |
|---|---|---|
| 1．機身接收服務與更新分派者 | 合法持有、可確定為 S5M2 的執行檔／共享庫／其他處理器模組，或對應來源；完整檔 SHA、韌體版本與部署身分 | 從端點路由或 IPC handler 到檔案 open/read、暫存路徑、UPD magic／欄位存取、下一層函式參數 |
| 2．專有認證／解碼實作及交接介面 | 上述接收者實際呼叫的模組、可核的 import／export、IPC command／結構或安全模組介面；不預設使用 AES 或硬體金鑰 | 輸入的精確範圍、完整性／驗簽對象、解碼順序、錯誤條件、輸出緩衝區與消費者 |
| 3．啟動與內容放置的證據 | 同版本部署 rootfs／init／服務設定、實際 DTB、已有合法 flash／RAM 或啟動紀錄，附來源與取得時間 | 接收服務在哪個環境執行、誰填充 gzip／Image／slram，建立分段／複製／重定位映射 |

【合理推論】最有效的下一份材料是**含上述接收服務與相依模組的同版本可讀機身系統映像／根檔案系統**，而非再一份只含受保護載荷的更新 BIN。若處理者位於另一處理器或安全環境，Linux rootfs 也可能只到 IPC 邊界；屆時需對端程式與訊息格式。這是取證優先序，不是已確定機身部署位置。

取得新材料前，不增加密鑰候選、不以高熵或 64／16-byte 長度判演算法、不用 S1M2／S5 代替缺失程式。本輪沒有新設備取證請求，也不要求拆機或刷寫。

## 驗證與交付停止

7 項格式合成控制通過；兩份 S5M2 ZIP／112 項目錄與歷史基線一致；六份官方包與 28 個指定函式 span 通過；81 個 DEX 方法位置／長度／寄存器／編碼分支目標與關鍵操作數斷言通過。合成模型涵蓋正常分片、誘發短讀、4 種選檔、3 種成功狀態與零長度公式。工具結果只支持列明斷言，不代表完整程式語義或實機驗證。

重現及精確本機路徑對照見 [REPRODUCE.md](REPRODUCE.md)。本輪無新增依賴，沒有重跑第一階段的全面 native／JADX／Ghidra 分析，沒有連接相機、執行目標程式或修改原始輸入。

**新增價值**是精確收斂 Android 末端與公開來源邊界、修正「尾端等於簽章」的跨機型套用，並把下一步缺失元件列為可驗收項目；不是現代 S5M2 解密或完整逆向成功。完成本次收尾後暫停，等待審查。
