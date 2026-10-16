# Lab 3.1.0：更新傳送末端的定點核查

輸入是 versionCode 22，不改動 APK／DEX，不執行 App。兩個 DEX：

| 檔案 | bytes | SHA-256 |
|---|---:|---|
| classes.dex | 7,341,852 | `02782fe6cf962788d1e5e76f707fc9d5e45669c205eaafee9bb8c50f2f5810ff` |
| classes2.dex | 5,047,724 | `4147c194d9814bac0f83e2120705b6e03524a3425d2492eafdbf547898736552` |

以下關鍵更新方法都在 classes2.dex。完整描述子、code_item、指令流 SHA、所有可見呼叫者位置在 [81 方法索引](results/android_method_index.json)。縮寫 `F` 表示 `com/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment`。CU 是 16-bit 單位，指令檔案位置 = `code_item + 16 + 2×CU`；不能把 CU 當 bytes。

## 選檔及完整路徑

【已驗證】`util/b0.M(String)` 取得 App 的 external files 子目錄，未取得時回到 filesDir 子目錄；`b0.A("camera_fw", zipPath, "")` 取 ZIP 路徑最後一段、再以第一個 `.` 前文字建立解壓目錄名稱，不是任意完整原路徑直接搬移。M／A 的實際呼叫及檔案操作均已定位，沒有在原 App 上執行 mkdir／delete。

`E1.c` 按 ZipFile 枚舉順序呼叫 `E1.b`，正規化斜線，跳過包含 `../` 的名稱；第一次 b=false 會停止，回傳已累積列表。`E1.b` 先把 File 加進列表才建立／寫檔，故非空列表不等於每個 entry 都完整寫入；這也不是完整 ZIP 安全性證明。父目錄條件依原 DEX 解讀，沿用第一階段對預設 JADX Java 的更正。

`z5/j4.c(CommunityDownloadInfoBean)`：code_item=`0x3ab264`，指令起點 `0x3ab274`。

| CU | 操作 | 含義 |
|---|---|---|
| `0x5e` | `E1.c(zip, extractionRoot)` | 得到累積 File 列表 |
| `0x6c..7e` | iterator／nonnull／`isFile()` | 按列表順序跳過不合條件項 |
| `0x80` | `File.getName()` | 只留 basename |
| `0x92..9e` | `Paths.get(root).resolve(name)`，跳出迴圈 | 父路徑被捨棄；選定路徑沒有在此重做 isFile 檢查 |
| `0xab` | `b0.f(zip)` | 程式設計為刪原 ZIP；本輪未執行 |
| `0xc5` | `setUpdateDownloadPath(path)` | 只保存路徑；由 `A1/b.run` case 4 交給資料庫更新 |

此選檔區未包含副檔名、UPD magic、ZIP entry size／CRC、韌體 hash／signature 比對的直接呼叫。這是指定區域的觀察，不是平台 ZipFile 內部行為或整個 App 的不存在證明。

【已驗證】合成選擇控制：根目錄 BIN 可選；先出現的 readme 會先選；目錄項跳過；`subdir/nested.bin` 被改成 `root/nested.bin`，後者在測試中不存在。這兩份官方 ZIP 均只有一個根目錄 BIN，因此沒有把合成不相容情境冒充官方檔案的實際故障。

`F5/f.c` 依相機／鏡頭記錄與版本條件保留更新項目，非空 downloadPath 也可保留，不在此讀 payload。`d7/a.apply` 的 catalog 轉換路徑把 downloadPath 初始化為空；`z5/g4.run` 的刪除 case 經 `util/v.v(path)` 刪檔或確認缺檔後清空資料庫／記憶體路徑。它們是路徑生命週期，沒有新證實的內容驗證器。多 case 合成方法的其他上下文不視為已完整語義恢復。

## 分片與原始短讀證據

【已驗證】`R5/e.b` 收到 prepare 回應，要求 data.bufsize>0、檔案 exists/isFile，記錄 `L=File.length()`，`B=bufsize`，`N=(int)ceil(L/(double)B)`，然後呼叫 x0。沒有同處的 L>0 條件。prepare JSON 的另一個 size helper `b0.y(File)` 則使用 available()，不能混同 File.length()。

`F.x0()`：code_item=`0x215d80`，指令起點=`0x215d90`。

| CU／實際檔案位移 | 原始操作 | 已核的資料關係 |
|---|---|---|
| `0x45`／`0x215e1a` | `mul-int v2,v0,v1` | offset 使用 int 的 i×B |
| `0x4b..53` | long 乘法、Math.min、轉 int、相減 | `len=(int)min(L,(long)(i+1)*B)-offset`；保留原 int 轉換界線 |
| `0x54`／`0x215e38` | `new-array v1,v0,[B` | 配置 len 大小、初始為零的 byte[] |
| `0x5e`／`0x215e4c` | `invoke-virtual {v3,v4,v5}, FileInputStream.skip(J)J` | 下一條是 read，無 move-result-wide |
| `0x61`／`0x215e52` | `invoke-virtual {v3,v1}, FileInputStream.read([B)I` | 下一條是 close，無 move-result |
| `0x64`／`0x215e58` | `close()` | 沒有 read-fully 迴圈或短讀修補 |
| `0x78`／`0x215e80` | `g8/z0.a(null,0,v1,len)` | 同一 v1 陣列、配置長度 |
| `0x97`／`0x215ebe` | `R5/h.b(String(len),String(i),body,deviceType,F)` | len 與序號進入更新 API |

每條原始 hex、寄存器與方法身分見 [instruction evidence](results/android_instruction_evidence.json)。上述檔案位移可從原 DEX 直接核對；不是只引用 JADX Java。

對固定 L、正 B、可表示且未溢位的範圍：序號從 0 起，offset=iB，最後一片使用剩餘長度。這兩份固件小於 int 最大值；沒有拿合成的大檔溢位冒充它們的故障。準備與 IO 期間如果檔案改變或發生短讀，原碼不以 read 回傳值重算 body 長度。

### 自製小檔案控制

執行的是自行編寫的 [SyntheticTransportTest.java](SyntheticTransportTest.java)，只用主機官方 JDK25 與新建合成檔案，沒有載入 APK 類別或開啟網路。

| 情境 | 觀測結果 | 支持及限制 |
|---|---|---|
| 21-byte 檔、B=8 | i=0/1/2；offset=0/8/16；len=8/8/5；完整讀取，重組一致 | 支持正常公式及同內容傳遞控制 |
| 已觀測 L=21，實際合成檔縮到 17 bytes | i=2、skip=16、read=1、配置/body 長度=5；body=`1100000000` | 誘發短讀後零尾端仍進 body；沒有證明未改變的一般檔一定短讀，更不是 Android 或機身測試 |
| 合成 L=0 公式 | N=0、首次配置 len=0 | 原 prepare 回應路徑仍可進 x0；沒有把這個公式控制當作實際更新行為 |

控制完整數據、選檔與狀態重建界線見 [synthetic_controls.json](results/synthetic_controls.json)。測試有記錄 skip/read 回傳值；**原 x0 沒有消費它們**。

## Body 到 HTTP／TLS

【已驗證】`g8/z0.a` 做陣列範圍檢查，`g8/y0` 保存原陣列及長度；`oa/g.a(Type)` 對 A0 request body 選 `oa/b` 身分 converter；`oa/b.a(Object)` 只 cast 並回傳。`oa/o0.c` wrapper 只轉交底層 body。

實際傳遞：`m8/b.a` CU `0x6b` 取得協定 sink，包成 `l8/c`→`u8/z`，CU `0x78` 呼叫 body.c。`y0.c`→`u8/z.S`→`u8/j.h0`→`z7/q.c` 的 `System.arraycopy`，將指定陣列區間原樣複製進分段緩衝區。

`l8/c.i` 限制超過宣告總長，close CU `0x0d..1c` 檢查已寫總量等於 expected length。**它能看到配置緩衝區的 5 bytes，無法知道其中只從檔案讀到 1 byte**。傳輸長度自洽不等於檔案內容完整。

HTTP/1：`n8/j.f` 選擇 chunked sink d 或已知長度 sink h；本 body 有已知長度。`n8/h.i` 轉交同內容緩衝區；chunked 分支添加協定長度及 CRLF。HTTP/2：`o8/C.f`→`K.g`→`H.i/a`→`A.z`→`M.b`，分配視窗與 DATA frame、轉交 buffer。`m8/a` 中 gzip 分支處理 response，不是對韌體 request body 做 gzip。

TLS 路徑 `l8/o.g` 建立 SSLSocket，握手／peer 檢查後，CU `0x152`→`U7/J0.y(Socket)` 取 OutputStream，經 `u8/c`／`u8/x.i` 寫出。`h6/d.verify` 的 digest 輸入是 peer certificate encoded bytes；不能當作韌體 hash。HTTPS 本身的加密與 HTTP framing 不能稱為韌體解碼／簽章驗證。

【陰性範圍】這條已追蹤 body／buffer 主鏈未恢復新的固件內容轉換或驗簽者；81 個選定方法的顯式 invoke 亦未直接呼叫第一階段 214 項 App native 宣告。這不排除其他反射／間接分派、平台 native、未列路徑或機身端實作。沒有宣稱所有網路／TLS 程式已完整逆向。

## 成功、失敗、取消及更新狀態

`R5/f.b`：code_item=`0x18bea8`。只有回應 body/data/header 存在、內層 Header.ResponseCode=200 且 Data.result=0 才走 `F.r0(200,null)`。其他碼／空資料／網路失敗進錯誤。此 Header.ResponseCode 是應用層回應欄位，不能單憑它當作獨立觀測到的 HTTP 200 或固件認證通過。

`F.r0`：code_item=`0x215278`。成功分支 CU `0x0f..11` 先 i++；`0x15..1b` 在 i<N 且 sending=true 時呼叫下一次 x0；`0x1f..2a` 在 i==N 時設 state=0 並顯示 DETAIL_TRANSFERRED。這條鏈按 ACK 推進，沒有在這個方法找到額外的 finalize／decode 請求。

失敗分支在 `v0()`（operation state=3 或 4）為真時改走 `w0`→abort-send；其他錯誤重設 i／sending、呈現訊息，state=2 時另排連線清理。x0 IO 例外亦按同一取消狀態選 abort 或錯誤。這不是保證所有崩潰／生命週期／競態分支已覆蓋。

【已驗證】`z5/i4.onClick` 的取消區 `0x5f..7c`：若目前 state=2，標 3，否則標 4。`z5/n4.onReceive` 收到 SD 卡狀態 1／3 且在 transferring UI 時標 4 並呈現錯誤。`F.w0` 設 sending=false 後呼叫 h6/a.g（abort-send）；`R5/g.b` 在正常／錯誤應用回應的各分支，及 `R5/g.a` 網路失敗均進 q0。因此本機清理回調不是相機已取消的證據。

【已驗證】`F.q0` 重設序號與 sending；state=3 會排連線清理，其他狀態改 0。`R5/g` 沒有把取消失敗另保留為已確認狀態。沒有執行 abort 或取消實驗。

【合理推論】最後一片 ACK 與取消交錯時，r0 的 i==N 分支沒有先看 v0，可覆蓋先前的 operation state 並顯示 transferred。自製狀態模型得到相同分支結果，**未量測 Android 上是否能觸發這個時序**，不稱為已證實實機問題。

### 直接相關的 BLE／Wi-Fi／HTTPS 狀態

- 【已驗證】`F.u0` 有配對記錄／BLE connected、版本／能力及 Wi-Fi connected 等前置門檻，不連 Wi-Fi 時導向連線畫面；本輪沒有發送任何無線請求。
- 【已驗證】`R5/e.b` 設 operation state=1。`H5/d.onCharacteristicChanged` CU `0x4ce` 比對 UUID `16726c35-52ef-4d00-868d-099549a90d9b`，取通知第一 byte；值 1 且 state=1 時於 `0x507` 改為 2，state=0 則觸發既有連線清理。只描述客戶端分支，未推定該 byte 是機身驗簽結果。
- 【已驗證】send／abort 從既有 authToken 及 `I5/c.d` gateway 建立 HTTPS 客戶端 `h6/h.l`；沿用第一階段 token 及憑證證據。本輪沒有重新解析所有配對／token 取得／GATT 特徵，也沒有連到相機驗證狀態遷移。

本輪新增的是資料與狀態邊界的證據。它們不證明可繞過機身驗證、不提供修改或傳送測試固件，也沒有恢復機身認證／解碼程式。
