# D：實際消費者與指定 API 全清單

版本及完整 SHA 見 [INPUT_MANIFEST](INPUT_MANIFEST.md)；每個 reviewed 方法的 DEX、code_item、instruction SHA 見 [EVIDENCE_INDEX](EVIDENCE_INDEX.md)。呼叫位置、register 與原始 invoke bytes 見 `results/selected_dex_evidence.json.gz`，輸入／輸出與 Caller 詳見 `results/java_dataflows.json`。

## 完整盤點的確切範圍

`scripts/inventory.py` 對既有 76,901 方法的 349,415 個 invoke 參照查詢並保存全部命中，不只保存摘要：

| 指定類別 | 位置數 | 解讀限制 |
|---|---:|---|
| java.security | 742 | 包含 exceptions、provider、key／certificate API，不全是運算 |
| javax.crypto | 100 | 定義內有呼叫，不等於 App 本次會選用該演算法 |
| TLS | 243 | 會話／trust／socket 與憑證 API，不能當成檔案驗證 |
| ZIP／gzip／Inflater／CRC 等 | 263 | 壓縮、容器與 CRC 各別追輸入 |
| Android／Java Base64 | 55 | 編碼，非加密 |
| JSON | 606 | 序列化／解析，非加密 |
| Parcel | 2,216 | 多為 IPC／Parcelable，非檔案加密 |
| ByteBuffer／ByteOrder | 1,126 | 緩衝區與數值轉換，不直接等於自訂格式已恢復 |
| Object streams | 14 | 物件序列化 |
| URL 編碼 | 10 | URL escape／decode |

合計 5,375 位置、1,630 方法，全部命中都有獨立原始 DEX method_ids／invoke operand 核查。`api_usage.json.gz` 保留模式，`java_factory_parameters.json` 保留 83 個 factory 的局部參數事實，未知的 wrapper／provider／mode／IV 不補猜值。另有 128 個已知 ASCII／hex／SDK BaseEncoding helper 參照；不把 Java API 前綴規則稱為涵蓋所有純 Java 自寫演算法。

73,540 string ID 以允許的演算法標籤 SHA 查詢，73 個命中再讀原始 MUTF8 bytes；111 個方法有允許標籤。這些仍是候選，**實際使用判斷必須回到 factory 參數與消費者**。沒有枚舉 key、解碼私密常數或輸出任意原始字串。

## 已核的主要流向

| 流程 | 輸入 → 操作 → 輸出／消費者 | 證據判斷 |
|---|---|---|
| `h6/d.verify` | peer certificate[0].getEncoded → SHA-256 → 與連線狀態中的指紋 MessageDigest.isEqual | 【已驗證】相機 HTTPS 指紋，非固件摘要 |
| RawProcessingConfigBean.hashFileNameToUint32 | String.getBytes → SHA-256 → 前四 bytes 以 big-endian fold 為 int | 【已驗證】實作；沒有 explicit DEX caller，實際功能使用未確認 |
| `I2/f.a` | cache key 去除特定字元；過長才 MD5＋hex；加副檔名／暫存標記 | 【已驗證】快取檔名用途；Lottie 關聯由 caller／cache 消費者支持 |
| `T2/s.create`、`T2/u.a` | SHA-256 digest pool → P2/q.b 更新 → digest＋hex → safe cache key | 【已驗證】有範圍的快取鏈；P2/q 具體分派未全解 |
| `R4/d.a` | SDK preference 公鑰表示 → Base64／RSA X509 parse → SHA1 → 修改首 byte／取前八 bytes／Base64 | 【已驗證】識別值派生，不是 RSA 加密；沒有讀取任何運行期 preference |
| `q4/k.<init>` | Play Store package signatures → SHA-256／Base64 → 比對 → 條件建立 review service binding | 【已驗證】該安全檢查資料流；混淆類的原始 SDK 歸屬保留推論層級 |
| GmsRpc.getHashedFirebaseAppName | Firebase app name → SHA-1 → SDK Base64UrlSafe helper | 【已驗證】SDK request metadata；不是相機 key |
| Adobe util `i.a` | String 參數 → SHA-256／hex → SDK caller | 【已驗證】helper 消費者；實際運行期內容／身分語義未確認 |
| OAuthHmacSigner／Sha256Signer | signature-base String、caller 提供的 secret fields → escape 組合／HMAC SHA1 或 SHA256 → SDK encoder | 【已驗證】SDK 程式路徑；App 是否選用、實際金鑰與 encoder 全部 alphabet 未確認 |
| PKCE.generateChallenge | verifier String → SHA-256 → URL-safe encoder → challenge field | 【已驗證】SDK 轉換；不宣稱所有 App 授權流程採用 PKCE |
| CommunityDownloadFragment.o0 | file／callback 輸入 → ZIP entries／name／isDirectory → community 檔案處理 | 【已驗證】非韌體 ZIP 消費者；所有錯誤／path-safety 分支未完成 |
| `h6/h.j`、`I5/d.a`、`h6/c` | 嵌入編碼值（遮蔽）→ Base64 decode → ASCII 篩選 → colon 組合 → Base64 encode → header interceptor | 【已驗證】編碼與篩選；不是加密，沒有解碼或測試真實憑證值 |

`I5/d.a([B)` 的 CU `0x0b` 檢查 NUL，`0x0e`／`0x12` 給 33／126 邊界，僅保留該範圍的 byte 再 append(char)。它會跳過空白與高位元 bytes、在首個 NUL 停止，**不是一般 UTF-8 decoder**。自製 `20 21 41 7e 7f ff 00 42` 模型控制結果為 `!A~`；沒有執行原方法。

命名空間本身只證明宣告。Google／Adobe 等具名 namespace 與 App `com.panasonic` namespace 分開；`h6`、`I2`、`T2`、`R4`、`q4` 等混淆套件依真實 consumer 分類，不能只看名稱宣稱全部第一方或第三方來源已證實。

## Native 密碼學與資料轉換

`native_api_candidates.json.gz` 保留 18 庫候選 symbols；`native_import_calls.json.gz` 另保留真實 PLT／BL。兩者層級不同。四個 `libavformat` 函式展示實際 TLS object／buffer／條件 inflate 消費者，詳見 [ARM64](ARM64_ANALYSIS.md)。`libcrypto`／`libssl` 大量內部演算法仍是庫內實作／呼叫候選，沒有把 exports 數量叫成完整語義或 App 實際協商算法。

LUT 是數值網格轉換；PNG CRC 的原輸入是 chunk type＋metadata。ZIP／gzip 是容器／壓縮。前輪的 PNG 控制與更新 ZIP 證據沿用，沒有為增加數量重跑。

## 陰性範圍與未知

【已驗證／有限陰性】指定兩個 DEX 的 explicit invoke 沒有 Android `security/keystore`／KeyPairGeneratorSpec type 命中，也沒有方法常數 `AndroidKeyStore`。Panasonic namespace 直接 crypto／Signature／MessageDigest 命中只有上述 filename hash 的兩個 digest API。這**不排除**混淆第一方包、平台 TLS、reflection、外部 provider 或計算式演算法。

【尚未確認】全部純 Java 演算法、第三方 SDK 的每個分派、native 內部 cipher／nonce／key 來源與運行期選擇仍未完成。沒有因此宣稱 App 不加密，也沒有建立韌體資料輸入這些加解密消費者的證據。
