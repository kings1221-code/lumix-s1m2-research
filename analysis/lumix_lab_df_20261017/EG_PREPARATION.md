# E／G 後續準備：尚未全面執行

版本 Lab 3.1.0／22。沿用前輪已核的 10 組 module entries 與本輪 `eg_preparation.json.gz`，不把 URI 宣告稱為已測通訊。

| 功能 | 具體入口／可用資料 | 下一個有範圍的核查 |
|---|---|---|
| BLE／配對 | Camera／CameraAdd／BluetoothConnection 等既有入口，Android BluetoothGatt 相關 explicit references | characteristic ID → read/write/notify → parser → state transition；不發送 GATT |
| Wi-Fi | WifiConnect、WifiNetworkSpecifier／ConnectivityManager 相關位置 | 連線 callback、network binding、token／fingerprint 的生產者消費者 |
| HTTPS | h6/a 的 59 個 client declarations、Retrofit Proxy、camera fingerprint 與各 client factory | 分開 camera、community、live／SDK client 的 URI／method／params／response／error |
| 遠端控制 | RemoteShootingActivity／RemotePhotostyle／ShutterRemoteControl 等既有 entry | 優先按 Y0 消息／狀態切分，對照 BLE／HTTPS 回應 |
| 圖庫傳輸 | CameraGallery／AutoTransfer／LlcService 等入口，新增 rating selector 2 | 檔案產生／URI／回應／清理，以及 rating writer 的格式邊界 |
| 直播 | LiveDelivery 系列 fragments／設定入口 | 串流設定、SDK 授權與媒體 transport 的實際選擇；不測第三方服務 |
| LUT／影像 | EditActivity selector 1、mergeCubeFiles、cube grid／writer、util/v.Q | parser、不同網格尺寸、數學模型與格式失敗條件 |

本輪模式命中 1460 個 explicit references：BLE 225、Wi-Fi/network 52、HTTP/TLS 1182、指定 LUT native 1；這些是 API／入口準備，不是 1460 個功能流程已還原。模式與原 CU 全部保留，也不聲稱這份小清單涵蓋每個 native／custom 通訊入口。

G 可優先採用完全自製的 finite LUT grid、輸出格式、ASCII 邊界、cache-name／摘要派生、ZIP／gzip／JSON 與原短讀控制。已做的 1044 LUT 模型及 ASCII／CFG 小控制是 D／F 所需核查；沒有全面執行 E／G，也沒有啟動 App、連相機、連未授權服務或讀取任何真實使用者憑證。

若未來需要原 App 執行，另提出獨立沙盒方案並取得使用者明確確認；目前交付停止在靜態證據與自寫模型。
