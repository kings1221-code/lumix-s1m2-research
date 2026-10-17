"""Render report reference tables from saved evidence; no new analysis."""
from common import *
def write(name,text):
    path=BASE/name;b=text.encode('utf-8')
    if path.exists():assert path.read_bytes()==b,name
    else:
        with path.open('xb') as f:f.write(b)
def main():
    rows_=load(RESULTS/'input_manifest.json')['inputs']
    lines=['# 原始輸入：Lab 3.1.0／versionCode 22\n\n',
      '【已驗證】25 原始 APK／DEX／ARM64 SO 的完整 SHA／大小與 A／B／C 一致，原件維持只讀。沿用既有 Google Play delivery 來源記錄，本輪沒有重新驗證 publisher signature 信任鏈，也沒有混入其他版本／缺失歷史鏡像。來源位置只用 SOURCE_ROOT token，實際使用者路徑不公開。\n\n',
      '| 類別 | 檔案／成員 | bytes | SHA-256 |\n|---|---|---:|---|\n']
    for r in rows_:
        name=r.get('member',r.get('path_token','').split('/')[-1]);lines.append(f"| {r['kind']} | `{name}` | {r['size']} | `{r['sha256']}` |\n")
    lines.append('\n完整機器清單見 results/input_manifest.json；私有既有索引與工具版本見 dependency_manifest.json。沒有提交這些原廠輸入或工具包。\n')
    write('INPUT_MANIFEST.md',''.join(lines))
    lines=['# 原始程式證據入口\n\n','所有方法屬 Lab 3.1.0／22；DEX SHA 於 INPUT_MANIFEST。CU 是方法指令起點的 16-bit code unit；file offset＝insns_offset＋2×CU。下面只是 reviewed Java 消費者，不是全部方法語義清單。\n\n',
           '| 流程 ID／方法 | DEX | code_item / insns file offset | 指令區 SHA-256 |\n|---|---|---|---|\n']
    for r in load(RESULTS/'java_dataflows.json')['flows']:
        e=r['evidence'];loc=e['location']
        lines.append(f"| {r['id']}<br>`{r['method']}` | {e['dex']} | `{hex(loc['code_item_offset'])}` / `{hex(loc['insns_offset'])}` | `{e['instruction_sha256']}` |\n")
    lines.append('\n全部 2231 個定點方法 location／SHA、11280 個原 invoke operands、591 個動態字串 ID operands 在 results/selected_dex_evidence.json.gz。字串原值不散布。\n\n原生四個新函式、九個 cube CFG、caller／callee、各條 import BL 的 file offset／bytes 在 native_evidence.json／native_import_calls.json.gz；原始指令全文和 C 留在私有 WORK。\n')
    write('EVIDENCE_INDEX.md',''.join(lines))
    cover=load(RESULTS/'native_coverage.json')
    lines=['# Native 分層覆蓋\n\n',
      '【已驗證】18 庫有相同摘要的 symbol／ELF 盤點；累計 65 個不同選定函式有反組譯證據。本輪對 13 個函式另匯出工具 CFG，並回核 1752 指令列；12 指令 helper 窗口另外計，不冒充新的完整函式。357 個 PLT／2428 個 BL 是指定 import 的線性位置盤點，不算 2428 個函式語義。\n\n',
      '| SO | dynsym 清單項（含 undefined） | 選定反組譯函式（累計） | 本輪明確工具 CFG | 有範圍模型控制 | 完整函式語義驗收 |\n|---|---:|---:|---:|---|---:|\n']
    for r in cover['libraries']:
        lines.append(f"| {r['library']} | {r['symbol_inventory']['dynsym_entries']} | {len(r['selected_disassembly_functions'])} | {len(r['explicit_tool_CFG_exports'])} | {'3 個 cube 有限模型／輸出' if r['bounded_synthetic_semantic_controls'] else '尚無'} | 0 |\n")
    lines.append('\n**不計算假的總語義百分比。** Dynsym 不含所有內部函式；Ghidra 函式識別、CFG export、C 產生、原指令回核與合成數學控制的分母不同。表內 0 是本輪沒有宣稱完整函式語義驗收，不表示函式沒有部分資料流成果。每個選定地址、SHA 與各層狀態見 results/native_coverage.json。\n')
    write('NATIVE_COVERAGE.md',''.join(lines))
    lines=['# 其餘 23 個失敗方法的審閱排序\n\n','42 次歷史 error／24 個不同方法維持原證據。以下不含已補部分 PNG 語義的 D；**所有 23 項仍未新增完整高階語義**。分數只用 direct file/security/network/reflection/JNI 等引用與 App 入口權重，CU 代表成本。分數 0 不表示安全或沒有功能。\n\n',
      '| 順序 | 分數 | 原方法 | DEX／code_item | CU | direct evidence 類別 |\n|---:|---:|---|---|---:|---|\n']
    for i,r in enumerate(load(RESULTS/'failed_method_ranking.json')['methods'],1):
        flags=', '.join(x['category'] for x in r['direct_evidence_categories']) or '未由指定 direct 模式分類'
        lines.append(f"| {i} | {r['review_priority_score']} | `{r['method']}` | {r['dex']} / `{hex(r['location']['code_item_offset'])}` | {r['cost_code_units']} | {flags} |\n")
    write('FAILED_METHODS.md',''.join(lines))
    print('Generated original-input, code-location, Native coverage and 23-method tables')
if __name__=='__main__':main()
