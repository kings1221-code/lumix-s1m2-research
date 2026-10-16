# 功能架構：已確認入口與可見關聯

本輪是 A／B 結構及定點語義。以下【已驗證】表示原 Manifest／navigation／DEX 定義與呼叫確實存在，**不表示整個模組已完整語義還原**。每個入口類別、方法數及直接 storage／communication／native 呼叫者與 CU 在 [module_entries.json.gz](results/module_entries.json.gz)。

| 入口組 | 實際入口例子 | 已有證據／尚缺 |
|---|---|---|
| 啟動、權限、設定 | AppLaunchScreenActivity、DeepLinkRouterActivity、PermissionConfirmationActivity、SettingActivity、DeviceInfoActivity | Manifest／DEX／intent 與直接呼叫；跨生命週期與權限失敗分支未逐一恢復 |
| 相機配對連線 | CameraFragment、CameraAddFragment、CameraBluetoothConnectionFragment、CameraWifiConnectFragment、CameraPairingFragment | navigation 與通信參照；完整 BLE／Wi-Fi 狀態機待 E |
| 遠端控制 | RemoteShootingActivity、RemotePhotostyleActivity、ShutterRemoteControlFragment | 127 方法入口集合；Y0 9,050 CU 失敗方法語義仍未完成 |
| 圖庫／傳輸 | CameraGalleryActivity、GalleryContainerFragment、AutoTransferFiles*、BurstActivity | 原始入口／storage 關係；完整傳輸、重試與檔案生命週期待 E |
| 影像／LUT | edit.EditActivity、LutFragment、ImageCropActivity | 新核 EditActivity.E0 → selector=1 Callable → mergeCubeFiles → 兩個 native 庫 → 檔案；其他編輯分支未完成 |
| 模板 | TemplateAddFrameActivity、TemplateSelectActivity、Template1SelectColorActivity | 73 方法集合及直接 storage／native 參照；不推定每個 UI 操作的完整結果 |
| 社群 | CommunityImageActivity、CommunityDownloadFragment、CommunityCreatorMainFragment | 入口與 storage 關係；遠端服務授權／所有 API 待 E，不連線測試 |
| 直播 | LiveDelivery* Fragment | navigation／DEX 確認；串流參數與第三方服務錯誤處理待 E |
| 韌體更新 | FirmwareDetailActivity、FirmwareUpdateListFragment、FirmwareUpdateDetailFragment | 保留兩階段已核 download／ZIP／chunk／HTTP chain；完整機身更新器仍缺 |
| 背景與通知 | LlcService、ForegroundService、LocationForegroundService、LlcMessagingService、PushNotification* | 元件及直接呼叫；實際啟動／通知傳遞情境未動態驗證 |

UI → Java／Kotlin → JNI → 通訊／儲存 → 回應的**可驗證完整片段**目前包括更新傳送與新 LUT native 子鏈；表中其他列提供可接續入口與直接關聯，不用推測補空白。沒有直接 communication 呼叫可能是委派到 view model／callback，不代表該模組無通信。

第三方分類可核 namespace 包括 AndroidX、Google/Firebase、Lottie、Glide、OkHttp／Retrofit、ONNX Java API 等；70 個版本檔是「包內版本宣告」，不是已證明每個 SDK 都啟用、也不是原生庫與上游 release 的身份驗證。短包名及共享合成類別所有權維持未知。
