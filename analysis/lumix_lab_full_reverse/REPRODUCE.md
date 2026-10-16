# 重現方式：A／B／C 中期

所有命令從倉庫根目錄以 PowerShell 執行。只讀取 APK／DEX／ELF 資料；執行的是可信分析工具與本專案腳本，不啟動 App、不載入目標 SO、不連相機。

## 不需要原廠樣本的交付核查

```powershell
$py = '.research-local/venv/Scripts/python.exe'
& $py analysis/lab_stage1_20261015/verify_delivery.py
& $py analysis/s5m2_stage2_20261016/verify_delivery.py
& $py analysis/lumix_lab_full_reverse/verify_delivery.py
& $py analysis/lumix_lab_full_reverse/scripts/query.py --method 'mergeCubeFiles'
```

前三項只核公開產物的 SHA／大小，不是重驗全部逆向語義。query 只需 Python 標準庫，讀公開 gzip 索引，不需 local_paths.json、APK 或工具安裝。

## 已使用工具及必要的本機依賴

- Python 3.12.14、pyelftools 0.33；環境沿用 `.research-local/venv/`。本輪沒有為數量安裝其他工具。
- Temurin Java／javac 25.0.4.1；本機 `.research-local/stage1/tools/jdk25/jdk-25.0.4.1+1/bin/`。
- JADX 1.5.6：`.research-local/tools/jadx/lib/jadx-1.5.6-all.jar`。本輪沿用既有 invoke index，只用 dexlib2 讀新 class／field metadata 及少數指令，不再全面反編譯。
- Apktool 3.0.3：`downloads/archives/tools/apktool_3.0.3.jar`，[官方 release](https://github.com/iBotPeaches/Apktool/releases/tag/v3.0.3)；SHA-256 `dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423`。執行前比對既存官方 release metadata；jar 及原始下載資訊不提交。
- Ghidra 12.1.4，AARCH64:LE:64:v8A；`.research-local/stage1/tools/ghidra/ghidra_12.1.4_PUBLIC/`。工具來源／工具包摘要沿用第一階段重現及輸入記錄。
- Apktool 內 bundled Baksmali 是 3.0.9-dev library；jar 經 shrink 後沒有可直接使用的 `baksmali.Main`，本專案 `SelectedSmali.java` 使用該實際 jar API，沒有下載其他 Smali 套件。

本機原始來源位置取自忽略的 `.research-local/local_paths.json` 中 `source_root`，或設定 `LUMIX_LAB_SOURCE_ROOT`。對應目錄是 `apk/` 的 5 APK、`extracted/base/` 的 2 DEX、`extracted/arm64/lib/arm64-v8a/` 的 18 SO，必須符合 INPUT_MANIFEST 的全部 25 項摘要。公開版本沒有原廠檔案；缺少原件者只能重核公開交付。

另須保留前階段的 `.research-local/stage1/dex_index_v2.jsonl`、`elf_inventory.json`、`ghidra_results/`、原始 JADX log、24 CFG、`analysis/lab_stage1_20261015/local/ghidra-project/Stage1`。它們的生成方式見前階段 REPRODUCE。JSONL 必須逐行讀取，不能對整個 Unicode 字串使用 splitlines，因為常數內可能包含 Unicode 分隔字元。

## 本輪實際執行流程

本輪各步驟均已執行並核查，但沒有把整條流程重新在第二個空目錄再跑一遍。重新產生時使用新的私有目錄；中間 log、SQLite 檔內排列、Ghidra 分析名稱及 Java 產物不承諾跨環境位元組完全一致。原始摘要、索引計數、選定指令及驗證結果應一致。

```powershell
$py = '.research-local/venv/Scripts/python.exe'
$java = '.research-local/stage1/tools/jdk25/jdk-25.0.4.1+1/bin/java.exe'
$javac = '.research-local/stage1/tools/jdk25/jdk-25.0.4.1+1/bin/javac.exe'
$jadx = '.research-local/tools/jadx/lib/jadx-1.5.6-all.jar'
$apktool = 'downloads/archives/tools/apktool_3.0.3.jar'
$s = 'analysis/lumix_lab_full_reverse/scripts'
$env:PYTHONIOENCODING = 'utf-8'
# 不覆寫本次證據，改用尚不存在的新目錄。
$env:LUMIX_FULL_WORK = Join-Path (Get-Location) '.research-local/full_reverse_replay'
$env:LUMIX_FULL_RESULTS = Join-Path $env:LUMIX_FULL_WORK 'results'
$env:LUMIX_FULL_PROJECT = Join-Path $env:LUMIX_FULL_WORK 'ghidra-project'
$env:LUMIX_FULL_DOCS = Join-Path $env:LUMIX_FULL_WORK 'generated-pages'
if (Test-Path -LiteralPath $env:LUMIX_FULL_WORK) { throw 'Use a fresh replay directory' }
New-Item -ItemType Directory -Path $env:LUMIX_FULL_WORK | Out-Null
$cfg = Get-Content -Raw -LiteralPath '.research-local/local_paths.json' | ConvertFrom-Json
$source = if ($env:LUMIX_LAB_SOURCE_ROOT) { $env:LUMIX_LAB_SOURCE_ROOT } else { $cfg.source_root }
$dex1 = Join-Path $source 'extracted/base/classes.dex'
$dex2 = Join-Path $source 'extracted/base/classes2.dex'
$classes = Join-Path $env:LUMIX_FULL_WORK 'java-classes'
New-Item -ItemType Directory -Path $classes | Out-Null

& $py "$s/apk_inventory.py"
& $py "$s/decode_apks.py"
& $javac -cp $jadx -d $classes "$s/DexStructure.java" 'analysis/lab_stage1_20261015/DexIndex.java'
& $java -cp "$classes;$jadx" DexStructure "$env:LUMIX_FULL_WORK/dex_classes.jsonl" $dex1 $dex2
& $py "$s/build_knowledge.py"
& $py "$s/build_modules.py"
& $py "$s/nested_inventory.py"
& $py "$s/elf_structure.py"

& $py "$s/prepare_semantics.py"
& $java -cp "$classes;$jadx" DexIndex dump "$env:LUMIX_FULL_WORK/semantic_instructions.jsonl" "$env:LUMIX_FULL_WORK/semantic_targets.txt" $dex1 $dex2
& $py "$s/prepare_dispatch.py"
& $java -cp "$classes;$jadx" DexIndex dump "$env:LUMIX_FULL_WORK/dispatch_instructions.jsonl" "$env:LUMIX_FULL_WORK/dispatch_targets.txt" $dex1 $dex2
& $javac -cp $apktool -d $classes "$s/SelectedSmali.java"
& $java -cp "$classes;$apktool" SelectedSmali "$env:LUMIX_FULL_WORK/smali" $dex1 $dex2
& $py "$s/dispatch_case.py"

& $py "$s/run_native.py"
& $py "$s/run_native.py" --refine
& $py "$s/run_native.py" --fix-prototype
& $py "$s/verify_findings.py"
& $py "$s/final_metadata.py"
& $py "$s/write_reference_pages.py"
& $py "$s/verify_checkpoint.py"
```

每個工具都應 exit 0；如果某步失敗，停止並檢查該步，不執行依賴它的下一步。正式證據寫入採不同內容拒絕覆寫；部分 Java dump 輸出沒有該 guard，所以整條重現必須採新 WORK。既有 libllc Ghidra 專案以 `-process -noanalysis -readOnly` 使用；新 cube 專案只在 WORK 建立，後續 refine／型別修正均唯讀，不修改原 SO。

run_native 的第一輪是既有兩個 libllc 函式及 cube seed 的直接內部 callees；refine 僅補該候選圖的下一層 4 個 helpers，並非擴大到所有函式。第三步只修正 `0x4e60` 的分析原型為 3 個指標參數，保存前後 C 摘要和必要呼叫片段。必須用 native_evidence 的原 ARM64 x2／caller 證據支持，不能單靠修正後 C 宣稱原始 struct 已恢復。

## 如何判讀通過與限制

- AXML：獨立 string-pool／chunk parser 對五份節點順序；Apktool 刻意把 uses-sdk 搬入 YAML，原 binary 的 minSdk=30／targetSdk=35 另外核對。這不是全部 attribute 或 resources.arsc 語義獨立驗證。
- 資源：base 有 692 unresolved-reference events、427 unique IDs，其他四個 split 無相同警告；Apktool exit 0 不代表全部資源解好。未獨立證明警告原因。
- DEX：12 個語義方法＋6 個 dispatcher 方法的 code_item／指令範圍對原 DEX；兩個指定方法的 Baksmali opcode 序列與 dexlib2 dump 一致。其他 24 失敗方法不因 CFG 存在而標成完整語義。
- ARM64：11 個本輪選定函式共 1,543 指令列依 PT_LOAD 回核原檔 bytes；累計 61 個不同選定函式不等於全部 18 庫語義完成。
- 合成控制只實行自行撰寫的 PNG iTXt CRC 對照；沒有執行 APK 或 native LUT 函式，沒有完成 LUT 插值數學等價測試。
- 最後 `verify_checkpoint.py` 重核原件摘要與保存證據一致性，不把報告寫的 PASS 當作語義重驗。`verify_delivery.py` 則供沒有原件的審閱者驗證公開交付。

重現結束後清除本 shell 的 LUMIX_FULL_* 變數或開新 shell，再做正式目錄的交付核查；不要把 replay 產物提交或覆蓋本次證據。
