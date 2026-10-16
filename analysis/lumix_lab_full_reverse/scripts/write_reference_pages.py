"""Generate exact input/coverage tables and preserve prototype-correction evidence."""
from common import *
DOCS=Path(os.environ.get('LUMIX_FULL_DOCS',BASE))
def md(path,text):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        assert path.read_text(encoding='utf-8')==text, 'Refusing to overwrite different document: '+str(path)
        return
    with path.open('x',encoding='utf-8',newline='\n') as f:f.write(text)
def main():
    inputs=load(RESULTS/'input_manifest.json')['inputs']
    table=['# INPUT_MANIFEST：Lab 3.1.0／22\n\n','【已驗證】本輪重核以下 25 個原始檔。來源沿用合法取得的 Google Play delivery 記錄，沒有新做 publisher signature 信任鏈；不把歷史鏡像的 XAPK／缺失 split 混入。原件不修改／執行／上傳。\n\n',
           '| 類別／檔案或 APK 成員 | bytes | SHA-256 |\n|---|---:|---|\n']
    for r in inputs:
        name=r.get('member',r.get('path_token','').split('/')[-1]);table.append(f"| {r['kind']} `{name}` | {r['size']} | `{r['sha256']}` |\n")
    table.append('\n檔案位置以 `<SOURCE_ROOT>/apk/`、`extracted/base/`、`extracted/arm64/` 指示；本機精確根位置只在忽略的 local_paths.json。五個 APK 所有成員另有 [apk_members.json.gz](results/apk_members.json.gz)。只對這個樣本目錄作核驗，不宣稱已搜遍電腦或不存在其他 App 版本。\n')
    md(DOCS/'INPUT_MANIFEST.md',''.join(table))
    cov=load(RESULTS/'coverage.json')
    table=['# COVERAGE：分母與證據層級\n\n',
           '| 層級 | 已覆蓋 | 沒有表示 |\n|---|---|---|\n',
           '| 原始身分／容器 | 25 inputs；5 APK 的 4867 members 完整 hash／CRC | publisher 簽章新驗證或 runtime 成功 |\n',
           '| DEX 結構 | 14812 class、48914 field、76901 method；349415 invoke；73540 string ID／hash | 全部方法語義／字串用途已懂 |\n',
           '| 資源 | 5 binary manifest 的節點／指定 SDK 屬性；13886 ID；28 nav 節點 | 427 個 unresolved IDs 已合併，或全部 UI 能重建 |\n',
           '| 動態／非同步 | 243 load/reflection 候選；680 指定 async sites；1 shared Callable case 有 operand 證據 | 反射／virtual／Rx／coroutine 全部解析 |\n',
           '| 失敗方法 | 24 CFG 沿用；本輪 1 項新增部分語義；0 項宣稱完整高階恢復 | 42 個不同方法，或所有 Java stub 都是真實異常 |\n',
           '| Native | 18 ELF 結構／符號相同輸入；累計 61 選定函式有 Ghidra 記錄 | 全部函式、struct 或原生庫已完整還原 |\n\n',
           '## 逐庫範圍\n\n| SO | 已定義 STT_FUNC dynsym 數 | 累計選定 Ghidra 函式 | 語義界線 |\n|---|---:|---:|---|\n']
    for r in cov['native_libraries']:table.append(f"| {r['library']} | {r['dynsym_defined_STT_FUNC']} | {r['selected_ghidra_functions_including_prior']} | {r['semantic_status']} |\n")
    table.append('\n**不以這兩欄相除作語義完成率**：dynsym 不含所有內部函式，Ghidra 的 identified functions 也包含 thunk／分析項目。libcube_merge 專案識別 68 項，本輪讀 9 個指定函式；libllc 專案識別 417 項，只作既有函式的定點核查。libcrypto 等大型庫多數內部仍未讀。新 1543 條指令逐條回原 ELF，不把重複核查的兩項 libllc 函式算新增。\n\nD／E／F／G 全面展開：未開始，等待使用者審查。\n')
    md(DOCS/'COVERAGE.md',''.join(table))
    original=load(WORK/'native_results/libcube_merge.so.json')
    before=next(f['c'] for f in original['functions'] if f['elf_va']=='0x51d0')
    fixed=load(WORK/'native_prototype_fixed/prototype_fixed.json')
    line=next(s.strip() for s in fixed['c'].splitlines() if 'FUN_00104e60(' in s)
    assert line.count(',')==2 and '&local_48' in line
    save(RESULTS/'prototype_correction.json',{'library':'libcube_merge.so','caller_elf_va':'0x51d0','callee_elf_va':'0x4e60',
         'original_generated_c_sha256':sha(before.encode()),'fixed_generated_c_sha256':sha(fixed['c'].encode()),
         'analysis_signature':fixed['signature'],'fixed_call_excerpt':line,
         'original_bytes_basis':'native_evidence.json ELF 0x5258..0x5274','project_mode':'-process -noanalysis -readOnly',
         'scope':'Only analysis type information corrected; input SO/APK unchanged; pointer types do not recover complete original C structs.'})
    print('Generated input and per-library coverage tables; verified corrected 3-argument C excerpt')
if __name__=='__main__':main()
