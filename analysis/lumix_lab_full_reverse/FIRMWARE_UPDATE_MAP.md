# 韌體更新：繼承模型與新分析的界線

【已驗證】保留[第一階段](../lab_stage1_20261015/README.md)及[第二階段](../s5m2_stage2_20261016/README.md)的原 SHA、DEX 位址及驗證工具：

```text
下載 ZIP → E1.c/b 解壓 → 第一個 isFile 項的 basename 重組
→ UpdateDownloadPath → send-prepare／bufsize
→ x0 單次 skip/read → byte[] request body → HTTP sink → ACK 推進
→ DETAIL_TRANSFERRED 或錯誤／abort／本機清理
```

read 回傳長度未消費、單片短讀零尾端、最後 ACK／取消模型的證據保持原範圍。客戶端傳送／UI 狀態不等同機身驗簽、解密或安裝通過。

本輪新增的資料消費者是 PNG metadata 與 cube LUT 子鏈，沒有建立它們接收韌體 byte[]／更新檔的關係。**沒有據此宣稱在整個 App 排除了韌體解密**。243 個反射／載入候選僅完成索引，F 的逐站追蹤仍待審查；沒有透過它們推測新的固件 consumer。

機身真正承接 firmware/* 的服務／分派者、其 UPD 認證／解碼模組及同版本部署映像仍缺；更多 App 索引不能代替這段原始程式。下一步取證要求沿用第二階段缺件表，不要求設備操作。
