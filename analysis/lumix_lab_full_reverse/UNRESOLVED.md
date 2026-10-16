# 未解項目與具體接續點

## A：輸入、資源及載入

- 25 原件及 4,867 APK 成員有完整摘要；原 Google Play delivery 身分維持既有紀錄，未新做發行者簽章信任鏈。
- 692 次 unresolved resource reference、427 個不同 ID 的跨 split 值合併未完成；公開檔列出全部 ID。不稱資源已完整還原。
- 243 個反射／load 候選只建立位置索引；參數、反射 Method 目標、optional／外部內容未逐一證明。
- 73,540 字串只公開 ID／位置／SHA；原始值保持本機，重要字串須先做用途與敏感值審查。

## B：語義與非同步

- 24 個失敗方法均保留結構 CFG；只有 PNG D 本輪新增部分語義，0 項宣稱完全高階恢復。
- 優先的具體接續點：RemoteShootingActivity.Y0（9,050 CU）的事件／狀態分支；MainActivity.a0 的 URI／媒體輸入；util/v.Q 的 LUT parsing；l0/h.e 的 JPEG marker 路徑。每項 descriptor／code_item 在 failed_method_progress。
- 680 是指定 async API 的候選數，Rx／coroutine／callback 的全部 capture／resume／反射分派沒有解析完。g5/k 的 selector=1 是已核的一個實例，不泛化到所有合成類別。

## C：JNI／Native

- splitYuv 實作存在，但 C++ mangled symbol／無已見 caller 不能建立 JNI runtime 綁定。外部或計算式註冊尚未排除。
- Google NativeOnCompleteListener 的 Java producer／callback 已定位，原生 provider 與 runtime 綁定未取得；不能稱永不執行。
- cube evaluator `0x5714` 的數學等價、浮點精度／邊界、LUT header/body 所有失敗輸入、allocator 整數及輸出錯誤處理仍需專門驗證。
- 大型 native 庫的內部函式、非匯出程式與全部 caller／資料結構遠未完成；未分析項逐庫列於 COVERAGE。沒有因列出 symbols 宣稱完整反編譯。

## D／E／F／G 審查門檻

全域 crypto／encoding map、完整功能 API 與通信狀態、由新反射／native 路徑回查 firmware、獨立測試環境的全面驗證均等待使用者決定；本輪只做 A／B／C 必要控制。若未來要執行原 App，先提出獨立沙盒方案並取得明確確認。

相機端仍缺同版本接收服務、更新分派、認證／解碼實作與部署映像／配置；這是固件處理鏈的阻塞，不是所有 App 靜態研究都已到終點。沒有新證據時不增加 key 枚舉、不假設缺的機身程式存在於 App。
