# 通訊：中期入口與已核邊界

**E 全面 API／BLE／Wi-Fi 模型尚未展開。** 元件／權限／導航及直接 communication 參照已在 A／B 索引，不能把它們當成所有通訊狀態已恢復。

已核更新部分沿用[第二階段 Android 報告](../s5m2_stage2_20261016/ANDROID.md)：firmware/send-prepare、firmware/send、firmware/abort-send 的 annotation、實際 caller／參數／body／應用層回應；BLE UUID `16726c35-52ef-4d00-868d-099549a90d9b` 與客戶端 operation state 的直接分支；Wi-Fi 前置門檻、既有 token、TLS peer fingerprint、HTTP/1／HTTP/2 sink。這些是客戶端證據，不代表相機更新認證通過。

新增可查位置：[元件與 permissions／intent](results/android_components.json)、[功能入口的 direct communication sites](results/module_entries.json.gz)、[所有原 DEX invoke references](results/dex_structure.json.gz)、[反射與指定 async candidates](results/dispatch_sites.json.gz)。

【尚未確認】其他所有 API 的 URI→caller→參數→回應／retry 語義、完整 GATT notification／write／狀態表、Wi-Fi/token 取得的全部路徑、外部服務與遙測實際啟用情況。API 名稱、Manifest INTERNET 或 usesCleartextTraffic 都不代替實際請求證據。未連接相機、網路服務或執行任何 App API；敏感值不公開。
