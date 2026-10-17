# D／F 重現與驗證

只進行原檔只讀靜態分析。以下命令執行自寫分析程式、JADX dexlib2、Ghidra、Capstone；**不執行／模擬 APK 或原 SO，不連相機／第三方服務**。不重新執行全面 JADX 反編譯，不下載新工具或 key。

## 公開交付可獨立核對

```powershell
$py = '.research-local/venv/Scripts/python.exe'
& $py analysis/lumix_lab_df_20261017/verify_delivery.py
& $py analysis/lumix_lab_df_20261017/scripts/query.py --api MessageDigest --limit 10
& $py analysis/lumix_lab_df_20261017/scripts/query.py --method 'RawProcessingConfigBean' --limit 10
```

這三項只需 Python 標準庫和公開交付，不需要原 APK 或 local_paths.json。交付 hash 通過不是逆向語義完整證明。

## 實際工具與本機依賴

沿用已驗證的 Python 3.12.14、pyelftools 0.33、Capstone 5.0.9、Temurin Java 25.0.4.1、JADX 1.5.6 與 Ghidra 12.1.4（AARCH64:LE:64:v8A）。本輪沒有新增安裝。原工具來源及包 SHA 沿用 A／B／C 和第一階段重現記錄；dependency_manifest 保存版本及原私有 metadata 的摘要。

必需資料：

- INPUT_MANIFEST 的同版本 5 APK、2 DEX、18 SO；`LUMIX_LAB_SOURCE_ROOT` 指定其根目錄，或 `.research-local/local_paths.json` 中的 source_root。
- `.research-local/stage1/dex_index_v2.jsonl`、elf_inventory.json、ghidra_results/ 及編譯的 `classes/DexIndex.class`；其源碼是 `analysis/lab_stage1_20261015/DexIndex.java`。
- `.research-local/full_reverse/dispatch_instructions.jsonl`、semantic_instructions.jsonl、native_results_refined/libcube_merge.so.json、Apktool decode/logs；`analysis/lumix_lab_full_reverse/local/ghidra-project/FullReverse`。生成方式見前階段 REPRODUCE。
- 先前三份公開 delivery manifests。本輪 verify 會核對 33／35／64 份產物。

原件缺失時不能重驗其 bytes；公開 metadata 與歷史報告不能取代原件。JSONL 逐行讀，不能用整個 Unicode 字串 splitlines 破壞內含分隔字元的字串值。

## 重現流程（從倉庫根目錄）

本輪各步驟實際執行並交叉核查；未在另一個全新目錄再重跑整條流程。重現採用新的 WORK／RESULTS／Ghidra project；所有不同內容拒絕覆寫，Java dump 也只能寫新檔。中間 Ghidra C／名稱及 log 不承諾跨環境 byte-identical，但輸入、位置、數量與核心原 bytes 檢查應一致。

```powershell
$py = '.research-local/venv/Scripts/python.exe'
$java = '.research-local/stage1/tools/jdk25/jdk-25.0.4.1+1/bin/java.exe'
$javac = '.research-local/stage1/tools/jdk25/jdk-25.0.4.1+1/bin/javac.exe'
$jadx = '.research-local/tools/jadx/lib/jadx-1.5.6-all.jar'
$s = 'analysis/lumix_lab_df_20261017/scripts'
$env:PYTHONIOENCODING = 'utf-8'
$env:LUMIX_DF_WORK = Join-Path (Get-Location) '.research-local/lab_df_replay'
$env:LUMIX_DF_RESULTS = Join-Path $env:LUMIX_DF_WORK 'results'
$env:LUMIX_DF_PROJECT = Join-Path $env:LUMIX_DF_WORK 'ghidra-project'
if (Test-Path -LiteralPath $env:LUMIX_DF_WORK) { throw 'Use a fresh WORK' }
New-Item -ItemType Directory -Path $env:LUMIX_DF_WORK | Out-Null
$cfg = Get-Content -Raw -LiteralPath '.research-local/local_paths.json' | ConvertFrom-Json
$source = if ($env:LUMIX_LAB_SOURCE_ROOT) { $env:LUMIX_LAB_SOURCE_ROOT } else { $cfg.source_root }
$dex1 = Join-Path $source 'extracted/base/classes.dex'
$dex2 = Join-Path $source 'extracted/base/classes2.dex'
$classes = Join-Path $env:LUMIX_DF_WORK 'classes'
New-Item -ItemType Directory -Path $classes | Out-Null
& $javac -cp $jadx -d $classes 'analysis/lab_stage1_20261015/DexIndex.java'

& $py "$s/check_inputs.py"
& $py "$s/inventory.py"
& $java -cp "$classes;$jadx" DexIndex dump "$env:LUMIX_DF_WORK/instructions.jsonl" "$env:LUMIX_DF_WORK/targets.txt" $dex1 $dex2
& $py "$s/dynamic.py"
& $py "$s/r8_and_paths.py"
& $java -cp "$classes;$jadx" DexIndex dump "$env:LUMIX_DF_WORK/extra_instructions.jsonl" "$env:LUMIX_DF_WORK/extra_targets.txt" $dex1 $dex2
& $java -cp "$classes;$jadx" DexIndex dump "$env:LUMIX_DF_WORK/review_instructions.jsonl" "$env:LUMIX_DF_WORK/review_targets.txt" $dex1 $dex2
& $py "$s/dex_evidence.py"
& $py "$s/java_flows.py"
& $py "$s/string_labels.py"
& $py "$s/manual_dynamic.py"

& $py "$s/resources.py"
& $py "$s/resource_uses.py"
& $py "$s/resource_raw_uses.py"
& $py "$s/native_import_calls.py"
& $py "$s/run_native.py" avformat
& $py "$s/run_native.py" cube
& $py "$s/native_evidence.py"
& $py "$s/lut_model.py"
& $py "$s/jni_registration_extension.py"
& $py "$s/audit_and_rank.py"
& $py "$s/verify.py"
```

**每步 exit 必須是 0，否則停止並檢查 log，不能在上一步失敗後依然執行依賴步驟。** 正式重現保留 public report 不變；`make_tables.py` 是本次報告渲染器，不應在已存在且證據不同的報告上覆寫。重現資料用自己的 RESULTS 比較，不把 replay outputs 提交。

JADX dump 只選 2187＋17＋53 個方法集合，另讀已存在的 7 個 dispatcher／Callable 方法；去重後 2231 個，不重跑 76901 方法的全面反編譯。`dex_evidence` 獨立解析 method_ids／proto／35c／3rc operands，11280 個保存位置含全部 5375 API 命中；不是信任 Java 輸出。

Ghidra avformat 建立新專案且不展開 callees；cube 使用既有專案 `-process -noanalysis -readOnly`，僅補 CFG。不改原 SO；完整 C／指令保留 WORK，公開僅必要 metadata／短證據。1752 函式指令列依 PT_LOAD 回核；357 PLT／2428 BL 另由 Capstone 檢查；二者不能相加當作函式完成量。

## 驗證結果的邊界

- `verify.py` 比較原警告與原 ARSC／AXML 的逐 ID 次數，692 events／427 ID 必須完全相符。`resource_uses` 的 decoded symbolic 搜尋 0 是保留的陰性對照，不是 raw consumer 不存在。
- 243 CFG 候選分類與 95 literal targets；manual_dynamic 另核一個七庫 finite-set；Room builder 是有證據的推論，沒有偷偷算成功。
- `lut_model` 執行自寫模型與獨立數學公式，1044 finite 案例＋組合／格式控制；`java_flows` 執行自製 ASCII 邊界控制；`verify` 執行四個 CFG 合流控制。**都不是原 App／SO 的執行或模擬。**
- `jni_registration_extension` 的 0 命中必須保留實際 pattern／range／原 SHA；不能擴張為 runtime／外部模組也不存在。
- publish guard 會檢查 UTF-8、原廠 executable extensions、使用者路徑、private-key／Bearer／GitHub token／Set-Cookie 模式；它是有界檢查，人工另核報告與必要證據，沒有把 regex 當成絕對無敏感資料的證明。

重現後關閉該 shell 或清除 LUMIX_DF_* 變數，再核正式交付。原件、tool caches、完整反編譯與合成測試檔不進公開 Git。
