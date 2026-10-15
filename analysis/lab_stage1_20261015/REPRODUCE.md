# 第一階段重現指南

先讀 [技術報告](README.md)。輸入必須是 [inputs.json](results/inputs.json) 的 Lab 3.1.0／versionCode 22；不同摘要須另立樣本，不可沿用本報告偏移。所有解析器以檔案為資料，不載入／執行目標類別或 SO。

## 工具與官方來源

前階段環境：CPython 3.12.14、pyelftools 0.33、Capstone 5.0.9、JADX 1.5.6、Temurin JRE 21.0.12.1+1。先依[環境指南](../offline_environment_20261015/README.md)建立 `.research-local/venv` 及 `.research-local/tools/jadx`。

本輪另外使用兩份官方 ZIP；本機原已保存，重新核對官方 SHA 後提取至 `.research-local/stage1/tools`，沒有下載不明工具或執行舊 downloads 腳本。

| 封存物 | 官方來源 | SHA-256 |
|---|---|---|
| ghidra_12.1.4_PUBLIC_20260921.zip | [NSA Ghidra 官方 release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build) | `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip | [Eclipse Adoptium 官方 release](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.4.1%2B1) | `00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283` |

這兩份 ZIP 置於 `downloads/archives/tools/`，或對 prepare_tools.py 使用 `--cache PATH`。該工具不自動連線，只接受相符摘要。版本、大小與來源見 [tools.json](results/tools.json)。JDK 用於編譯本研究自己的解析器與 Ghidra script；目標 APK 不在 Java classpath。

## 目錄與版本規則

- `SOURCE_ROOT`：原有 `s5m2-apk`，含 `apk/`、`extracted/base/`、`extracted/arm64/`。不在其中寫結果。
- `.research-local/local_paths.json`：至少包含 `{"source_root":"C:/path/to/s5m2-apk"}`，不提交本機絕對路徑。
- `.research-local/stage1/`：本輪原始 DEX 參照索引、完整指令轉儲、新反編譯原碼、日誌、Ghidra C／設定／快取，全部不提交。
- `analysis/lab_stage1_20261015/local/ghidra-project/`：Ghidra 專案，忽略追蹤。專案路徑不能含以點開頭的目錄元素。
- `results/`：允許公開的方法／地址／控制流／摘要與精簡證據；沒有原廠 APK／SO／固件或完整反編譯原碼。

下列完整流程用於**新 checkout、尚無 stage1 輸出的工作副本**；既有輸出先保留。native_inventory 與前置盤點拒絕既有輸出檔；不要以刪除原研究檔案取得可重跑狀態。只要核對本次已保存結果，可直接執行末節驗證。

## 依序執行

從倉庫根執行；`$sourceRoot` 指向符合清單的原始目錄。

```powershell
$python = '.\.research-local\venv\Scripts\python.exe'
$sourceRoot = 'C:\path\to\s5m2-apk'
$work = Join-Path (Get-Location).Path '.research-local\stage1'

& $python -I analysis\offline_environment_20261015\audit_resources.py `
  --source-root $sourceRoot --output .research-local\stage1_preflight
& $python -I analysis\offline_environment_20261015\verify_environment.py `
  --source-root $sourceRoot --output .research-local\stage1_environment.json
& $python -I analysis\lab_stage1_20261015\prepare_tools.py

$java21 = '.\.research-local\tools\jre\jdk-21.0.12.1+1-jre\bin\java.exe'
$java25 = '.\.research-local\stage1\tools\jdk25\jdk-25.0.4.1+1\bin\java.exe'
$javac = '.\.research-local\stage1\tools\jdk25\jdk-25.0.4.1+1\bin\javac.exe'
$jar = '.research-local\tools\jadx\lib\jadx-1.5.6-all.jar'
$dex1 = Join-Path $sourceRoot 'extracted\base\classes.dex'
$dex2 = Join-Path $sourceRoot 'extracted\base\classes2.dex'

# 全量重跑 JADX。此次預期 exit 3 / 42 errors，不能誤報為無錯誤反編譯。
& $java21 -Xmx4g "-Duser.home=$work\java-home" -cp $jar jadx.cli.JadxCLI `
  --log-level debug -d "$work\jadx_replay" `
  (Join-Path $sourceRoot 'apk\com.panasonic.jp.lumixlab-22.apk') `
  *> "$work\jadx_replay.log"
[System.IO.File]::WriteAllText("$work\jadx_exit.txt", [string]$LASTEXITCODE)

# 讀原始 DEX：定義、native flags、invoke 參照與指令偏移。
& $javac -cp $jar -d "$work\classes" analysis\lab_stage1_20261015\DexIndex.java
$classPath = "$work\classes;$jar"
& $java25 -Xmx3g -cp $classPath DexIndex index "$work\dex_index_v2.jsonl" $dex1 $dex2
& $python -I analysis\lab_stage1_20261015\native_inventory.py `
  --libraries (Join-Path $sourceRoot 'extracted\arm64\lib\arm64-v8a') `
  --output "$work\elf_inventory.json"
& $python -I analysis\lab_stage1_20261015\derive_indexes.py
& $java25 -Xmx3g -cp $classPath DexIndex dump "$work\selected_instructions.jsonl" `
  "$work\dex_targets.txt" $dex1 $dex2

# 只匯入四個選定 ELF，呼叫者地址由實際 ELF 表／符號產生。
& $python -I analysis\lab_stage1_20261015\run_ghidra.py
& $python -I analysis\lab_stage1_20261015\verify_evidence.py
& $python -I analysis\lab_stage1_20261015\publish_report_data.py
```

任何非預期失敗都先停止相依步驟。DexIndex 的 index 模式本次為 76,901 方法，dump 為 131 選定方法；dump 是本機完整資料，不隨庫分發。獨立 dex_offsets.py 解析 class_data 取得 code_item；指令 CU 為 16-bit 單位，檔案位移為 `code_item + 16 + 2*CU`。

native_inventory.py 使用所有 18 個 ELF 的 dynsym／DT_NEEDED 及 RELA-aware 對齊 triple 掃描。掃描只產生候選；verify_evidence.py 再對回 Ghidra 的實際類別／表／數量／RegisterNatives 消費者。這個模式不保證找到計算式或非標準動態表。

Ghidra script 只反組譯／反編譯，不啟動目標。若專案已存在且只需重新匯出新 script 的證據，用 `run_ghidra.py --reprocess`，會處理已匯入程式並停用新一輪自動分析；沒有覆寫原 SO。

## 已發生並修正的環境問題

1. Windows batch 啟動在本工作區的引數／Unicode 路徑組合出現語法錯誤，未啟動分析。改由官方 Utility.jar 的 `ghidra.Ghidra` Java 入口，以 argv 陣列啟動。
2. 預設設定目錄被 sandbox 拒絕；設定 application.settingsdir／cachedir／tempdir 到本研究目錄，重跑獲准的可信工具。
3. Ghidra 不接受專案路徑包含 `.research-local` 這類點開頭元素；專案改放本研究的忽略目錄 `local/`。
4. Log4j XInclude 對此 Unicode 路徑仍有訊息，自動分析亦出現無效目標警告。最終實際取得四份非空 JSON、52 函式與已核指令，不以 exit=0 代替驗證。原樣保留本機日誌；沒有修改官方工具。

## 驗收與仍未完成的部分

```powershell
# 需要本機原輸入及本次 Ghidra／DEX 輸出：
& .\.research-local\venv\Scripts\python.exe -I analysis\lab_stage1_20261015\verify_evidence.py

# 不需 APK，只核公開交付檔案的精確 SHA：
& .\.research-local\venv\Scripts\python.exe -I analysis\lab_stage1_20261015\verify_delivery.py
```

本次實際驗收：25 個輸入未變、全部 76,901 方法偏移／長度與 flags 吻合、24 個結構 CFG 可重建、15 項動態表符合 DEX 宣告與註冊消費者、52 個 Ghidra 函式中 8,154 條指令位元組吻合，關鍵 send buffer／skip-read／父目錄分支核查通過。[機器摘要](results/scope_verification.json)。

CFG 的例外邊是保守近似，完整高階 Java 語義、所有反射／間接分派及全部原生函式資料流沒有因此通過。機身端原始程式與 D／E 方向仍待後續決定；沒有部署、設備通訊或固件驗證成功的宣稱。

完整 CFG 結構資料以 `results/failed_method_cfg.json.gz` 保存；用 Python gzip 解開即可讀 JSON，未壓縮內容的 SHA 列於 `failed_method_cfg_index.json`。這是控制流 metadata，不是原 DEX 或其完整指令副本。
