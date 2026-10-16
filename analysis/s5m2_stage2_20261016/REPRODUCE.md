# 第二階段：重現、檔案位置與驗證界線

本輪使用 Windows／PowerShell、既有 Python 3.12.14、官方 Temurin JDK 25.0.4.1+1、JADX 1.5.6 內附 dexlib2／Gson。**沒有新增套件、沒有執行 APK／SO／固件，也沒有重跑 JADX 全量反編譯或 Ghidra。** 工具原始摘要沿用第一階段 `results/tools.json`，本輪使用及環境見 `results/environment.json`。

不要使用 Python `-O`，核查程式的斷言需要保持啟用。程式以 `-B -X utf8` 執行；此輪修正了開發時誤用 `-I` 導致 sibling module 無法匯入的啟動問題，沒有修改分析工具或原輸入。

## 本機實際位置

下列路徑使用公開 token；本機精確對照保存在忽略追蹤的 `.research-local/stage2/paths.json`，避免把使用者目錄身分寫入 Git。`<LOCAL_PROJECTS>` 指本機既有研究專案根目錄：

- 第一階段已提交：`analysis/lab_stage1_20261015/`；提交 `69333e24675fcdbe2f7d00481a3360af78a1ea9e`。
- APK／DEX／SO 原件：`<SOURCE_ROOT>/`。兩個 DEX 在 `extracted/base/`，18 庫在 `extracted/arm64/lib/arm64-v8a/`；未寫入此樹。
- V3.1 原 ZIP：`<LOCAL_PROJECTS>/s5m2-github-https-github-com-siegfried82/stage12/inputs/S5m2_V31.zip`。
- V3.7 原 ZIP：本倉庫 `downloads/samples/S5M2/S5m2_V37.zip`。
- 六份官方包：`<LOCAL_PROJECTS>/s5m2-github-https-github-com-siegfried82/stage3/inputs/`，檔名為 `S5M2_Ver1_uboot.tar.gz` 等，完整名稱在 `results/inputs.json`。
- 第一階段完整輸出：本倉庫 `.research-local/stage1/`（原始索引／日誌／完整 C／Java）；Ghidra 專案在 `analysis/lab_stage1_20261015/local/ghidra-project/`。
- 第二階段完整 DEX 轉儲／選定 OSS 原檔／官方 HTML／合成檔：`.research-local/stage2/`。`android_instructions_final.jsonl` 為 78 方法，`android_paths_extra.jsonl` 為 3 方法；`oss_selected/` 保存從精確 tar 成員只讀取出的來源副本；`synthetic/` 只有自製測試檔。
- 原始路徑配置：`.research-local/stage2/paths.json`，不提交。原下載目錄與附件均未列入本次提交。

原廠輸入及完整反編譯／來源副本不由本研究提交散布；Git 交付只含自行編寫的工具、報告、方法／範圍／摘要索引與必要的精簡指令證據。

## 只核驗已保存結果

從倉庫根目錄執行：

```powershell
$python = '.\.research-local\venv\Scripts\python.exe'
& $python -B -X utf8 analysis\s5m2_stage2_20261016\verify_delivery.py
& $python -B -X utf8 analysis\s5m2_stage2_20261016\validate_results.py
# 若原輸入與 paths.json 都在本機，再核完整原檔及所有精簡指令 bytes：
& $python -B -X utf8 analysis\s5m2_stage2_20261016\validate_results.py --with-inputs
```

公開 metadata 的交叉核對不替代原檔重驗。`final_validation.json` 記錄本輪實際 35 項身分與原 DEX excerpt 的核查，沒有把舊全包掃描重新標成新掃描。

## 在新輸出目錄重現本輪定點核查

需要合法持有且摘要相符的輸入、第一階段已保存的 dex_index_v2.jsonl／完整 JADX 錯誤日誌／DexIndex class，以及上述兩個歷史提交。缺少第一階段完整產物時，該部分須依第一階段指南另行重現；本輪沒有為此重跑全面分析。

以下工作目錄及結果目錄必須尚未存在；程式使用 exclusive create 拒絕覆寫證據。請把範例輸入位置替換為實際位置。

```powershell
$python = '.\.research-local\venv\Scripts\python.exe'
$env:LUMIX_STAGE2_WORK = Join-Path (Get-Location) '.research-local\stage2-replay-new'
$env:LUMIX_STAGE2_RESULTS = Join-Path $env:LUMIX_STAGE2_WORK 'results'
$scripts = 'analysis\s5m2_stage2_20261016'

& $python -B -X utf8 "$scripts\prepare_inputs.py" `
  --source-root 'C:\path\to\s5m2-apk' `
  --oss-root 'C:\path\to\six-official-archives' `
  --v31-zip 'C:\path\to\S5m2_V31.zip' `
  --v37-zip 'C:\path\to\S5m2_V37.zip'
& $python -B -X utf8 "$scripts\preserve_stage1.py"
& $python -B -X utf8 "$scripts\test_structure.py"
& $python -B -X utf8 "$scripts\firmware_structure.py"
& $python -B -X utf8 "$scripts\oss_boundary.py"
& $python -B -X utf8 "$scripts\compare_oss_selected.py"
```

官方頁面採**本機已保存快照**核對。複製本次 `.research-local/stage2/official_pages/` 整目錄到新工作目錄同名位置後：

```powershell
& $python -B -X utf8 "$scripts\official_pages.py"
```

如果沒有這份 HTML 快照，以上步驟會明確失敗。只有需要新的官方網頁來源紀錄時才加 `--fetch`，它僅連 Panasonic 公開網站，會建立新快照及當次時間／hash；不能期待網站日後內容與本輪摘要相同。這是另一次來源盤點，不是本輪離線核查的隱藏網路依賴。

```powershell
& $python -B -X utf8 "$scripts\prepare_android_targets.py"
$java = '.\.research-local\stage1\tools\jdk25\jdk-25.0.4.1+1\bin\java.exe'
$javac = '.\.research-local\stage1\tools\jdk25\jdk-25.0.4.1+1\bin\javac.exe'
$jar = '.research-local\tools\jadx\lib\jadx-1.5.6-all.jar'
$source = 'C:\path\to\s5m2-apk'
$dex1 = Join-Path $source 'extracted\base\classes.dex'
$dex2 = Join-Path $source 'extracted\base\classes2.dex'
$classPath = ".research-local\stage1\classes;$jar"

& $java -Xmx2g -cp $classPath DexIndex dump `
  "$env:LUMIX_STAGE2_WORK\android_instructions_final.jsonl" `
  "$env:LUMIX_STAGE2_WORK\android_targets_final.txt" $dex1 $dex2
& $java -Xmx2g -cp $classPath DexIndex dump `
  "$env:LUMIX_STAGE2_WORK\android_paths_extra.jsonl" `
  "$env:LUMIX_STAGE2_WORK\android_paths_extra.txt" $dex1 $dex2
& $javac -cp $jar -d "$env:LUMIX_STAGE2_WORK\classes" "$scripts\SyntheticTransportTest.java"
& $java -cp "$env:LUMIX_STAGE2_WORK\classes;$jar" SyntheticTransportTest "$env:LUMIX_STAGE2_WORK\synthetic"
& $python -B -X utf8 "$scripts\verify_android.py"
& $python -B -X utf8 "$scripts\build_catalog.py"
& $python -B -X utf8 "$scripts\validate_results.py" --with-inputs --record

Remove-Item Env:LUMIX_STAGE2_WORK
Remove-Item Env:LUMIX_STAGE2_RESULTS
```

任一步非預期失敗應停止相依步驟，保留原輸出；不要刪除舊結果來取得可重跑狀態。重現中的 Git 起始狀態、日期／來源頁及 private path 配置可能不同，不應冒充本次原始紀錄。Python JSONL 以檔案逐行讀取，不用 str.splitlines()，以免把字串內的 Unicode 分隔字元錯切為 JSON 記錄。

## 驗收限制

- 格式工具由 S5M2 的兩個精確輸入與歷史逐項資料交叉核對；7 項合成控制測 raw 偏移／destination 混用、重名、完整載荷、CRC、長度、重疊、內頭與尾部。只接受本批觀察到的無額外尾段配置，不聲稱通用全部 UPD 版本解析器。
- OSS 重新讀的是指定來源／函式 span；全包 regex 掃描明確引用歷史真實結果，沒有重跑。`lexical_callees`／callers 只是文字範圍索引，不是完整 AST／link／runtime graph。
- 81 方法取得原始指令及位置／長度／寄存器／分支目標核對；沒有因此宣稱每個多 case 方法全部高階語義正確。短讀與取消測試是自行重建控制，原 APK 不執行。
- 官方來源、CRC32、SHA 自洽與 HTTP／UI 成功各有其證據範圍，均不代替機身 UPD 認證、載荷解碼或安裝成功。
- 未取得機身更新處理者即停止 E3；沒有擴展金鑰掃描、設備通訊或其他機型替代。
