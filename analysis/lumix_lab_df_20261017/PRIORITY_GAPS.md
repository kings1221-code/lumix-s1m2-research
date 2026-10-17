# 優先缺口、已解除項與所需證據

## 兩項 JNI：仍未解決，不能以補充索引充當綁定

【已驗證】本輪重核 214 項原對照；兩項狀態沒有被改為成功：

| 宣告／實作 | 新檢查 | 真正欠缺 |
|---|---|---|
| LlcApplication.splitYuvArrayToYAndUv；libllc 0x16e18 的 C++ mangled 實作 | 全 18 dynsym 與相關 symbol relocation；libllc 全 RELA addend=0x16e18；allocated non-executable PROGBITS 的精確 uint64 pointer；精確 NUL method-name bytes；Java explicit caller／已解字面 reflection | 可核對的 RegisterNatives 寫入／loader 綁定／真正 Caller；C++ 改名實作本身不是普通 JNI 綁定 |
| Google NativeOnCompleteListener.nativeOnComplete | onComplete 的一個 direct caller 保留；createAndAddCallback 無 explicit caller；同 18 庫精確名字／symbol／relocation 範圍 | 提供該回調的實際 native module 或註冊程式；不能假設某個相機庫提供它 |

兩個 method 的精確 NUL 名稱、指定 pointer／addend 掃描這次均為 0，實作與各 section 範圍／SHA 保留於 jni_registration_extension。這不涵蓋 runtime-created strings、計算式指標、外部 Google module、平台庫或運行期註冊。**「這 18 庫未取得綁定證據」不同於「方法不會執行」。**

## 427 個 resource reference：ID／原值與消費者已解除

【已驗證】427 ID 全為 drawable；原 xxhdpi ARSC 的 428 個 config-preserving entries 對到原 ZIP member 並核 CRC／SHA。完整 entry index／flags／config／原始 value bytes／offset 在 resource_resolution，沒有以名稱字典覆蓋重複 ID 的不同 config。

原 base ARSC 有 10 個 style value 引用，原 binary XML 有 682 個 attribute 引用；**與原 692 次警告逐 ID 次數完全吻合**。涵蓋 259 個 XML members，包括 activity_remote_shooting、activity_settinng、firmware list／checkbox、LUT、camera、live delivery 等。這回補了功能入口與設定畫面所需的圖像值對應。

【與解碼文字結果衝突】既有 decoded XML 的 symbolic drawable 搜尋回傳 0，原 binary 卻有上述 682 個引用。故 decoded 資料的缺失不代表原資料沒有分支／參照。原 APK、decoder outputs 及 warning logs 全部保留，沒有 patch APK 或假造新的完整解碼目錄。

【尚未確認】Android 實際 configuration 選擇、完整 style/theme、所有 DEX resource consumer、點擊／設定狀態機與 UI rendering。解除 427 個 ID 缺口不等於整個資源／功能還原完成。

## 23 個 JADX 失敗方法：已排序，語義不冒充完成

`failed_method_ranking.json` 對其餘 23 項保存 code_item、CU、direct calls、JNI／file／security／network／reflection 類別及可重現分數。它是 review 排序，不是漏洞嚴重度，也不是語義恢復百分比。

優先順序：

1. `util/v.Q(BufferedReader, EditLutListBean)`，1012 CU：檔案／LUT parser，先核所有 header／triplet／狀態與 malformed 分支。
2. `MainActivity.a0(MainActivity,boolean,Uri)`，1377 CU：URI／媒體入口與實際檔案／轉交；優先於純 framework 佈局。
3. `RemoteShootingActivity.Y0(K5/Q0)`，9050 CU：大量控制事件／狀態分支；按具體輸入消息切分，不從一個大 Java stub 推論分支不存在。
4. `l0/h.e(l0/b,int,int)`，478 CU：JPEG marker 路徑與 buffer 邊界。
5. `p6/k.r(Object)`，1226 CU：有檔案 I/O 的協程／狀態路徑；需補 capture／resume 條件。

完整 23 表見 [FAILED_METHODS](FAILED_METHODS.md)。前輪 PNG D 的部分語義保留；本輪沒有把另外 23 個標成完整高階恢復。

## 要繼續找真正的相機韌體解碼器，具體缺什麼

App 這邊仍有 reflection／interface／SDK provider 與 native 內部可分析；目前沒有建立新的 firmware byte stream → decoder 關係。要閉合**機身**鏈，缺的是接受 firmware/send 等請求的同機型接收服務／分派者，檔案 spool／UPD parser，及認證／解碼／解壓／載入的專有處理模組和部署映像／配置。只有 API 宣告、官方公開元件或另一機型的 loader 不能補上這段。

所需原始證據是有來源與 SHA 的該元件可分析二進位／合法原始碼，或能證明輸入、呼叫順序與輸出落點的可信同版本紀錄。沒有它們時停在具體缺件，不能靠算法常數、文件名稱或其他機型補完整條鏈。本輪未提出設備、維修工具、密鑰或授權繞過操作。
