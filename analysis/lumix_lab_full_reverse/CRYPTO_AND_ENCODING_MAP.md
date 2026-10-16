# 密碼學與編碼：A／B／C 中期已核種子

**D 全面盤點尚未展開，等待使用者審查。** 本頁只保存已有真實資料消費者，不將 libcrypto／libssl 的符號或常數直接提升為 App 的實際使用演算法。

| 資料路徑 | 狀態／輸入與輸出 | 證據與限制 |
|---|---|---|
| h6/d.verify | 【已驗證】SSL peer certificate encoded bytes → SHA-256 digest／比較 | 前階段原 DEX 已核，處理憑證指紋；不是韌體 payload 驗證。[第二階段](../s5m2_stage2_20261016/ANDROID.md) |
| l0/h.L／M | 【已驗證】PNG chunk type＋EXIF／XMP bytes → CRC32 → big-endian chunk CRC | 原指令、Baksmali／writer consumer；合成 iTXt 控制通過；不是簽章／韌體 hash。[DEX_ANALYSIS](DEX_ANALYSIS.md) |
| ZIP／gzip 容器 | 【已驗證】五 APK、三 nested ZIP、publicsuffix gzip 的解壓／成員 hash／CRC | 格式驗收僅對實際列明輸入；不代表整體 App 自訂資料都已辨識 |
| cube LUT | 【已驗證】文字頭部／double triplets → 網格資料 → writer；【合理推論】分區插值 | 原生 caller／callee／輸出鏈，數學等價及所有 malformed cases 尚未測試 |
| AES／RSA／ECC／HMAC／Keystore 等 | 【尚未確認】本輪尚未建立全域實際使用圖 | 不從可用 SDK／native symbol 宣稱 App 使用某模式、key 或 IV；D 待審查 |

沒有提取 Token／私人憑證、破解 key、繞過驗證或執行原 App。金鑰來源、Nonce／IV、完整資料轉換 call graph 仍是 D 的待辦；沒有為填滿報告自行命名演算法。
