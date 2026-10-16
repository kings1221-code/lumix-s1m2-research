# 全 App 靜態研究進度

2026-10-16。本輪授權是 Lab 3.1.0／versionCode 22 全 App 靜態研究，先交付 A／B／C 中期報告；本檔是續作入口，避免重新全面掃描。

- 基線：第二階段 `2e076ce1e455fec7ed7ea0715b2347378f837c45`；第一階段 `69333e24675fcdbe2f7d00481a3360af78a1ea9e`。
- 獨立分支：`codex/lumix-lab-full-reverse-20261016`。原有未追蹤 downloads／附件保留。
- **A 中期盤點已交付**：25 原始檔重核；5 APK／4,867 members 完整大小、SHA、CRC；5 binary Manifest、元件、權限、resource ID、nested containers。資源完整語義仍缺 427 個 unique unresolved references 的解決與 split 合併。
- **B 中期索引及定點語義已交付**：14,812 classes、48,914 fields、76,901 methods、349,415 invokes、73,540 string ID／SHA；10 組入口、非同步／反射候選；12＋6 個定點 raw DEX 核查；2 個 Baksmali opcode 序列控制。24 個失敗方法保留 CFG，本輪只補 1 個部分語義，0 個宣稱完整高階恢復。
- **C 中期盤點及定點 native 分析已交付**：18 ELF 結構及相同摘要的既有 dynsym；新增 cube merge 的 9 個函式；本輪 11 個選定函式共 1,543 指令列逐位元組回核。加上既有 52 個不同函式，累計 61 個；不稱全部 native 語義已完成。
- 新證據：共享 Callable 的 selector=1 → mergeCubeFiles → libllc → libcube_merge，及 LUT reader／grid composition／writer／cleanup 的實際呼叫關係。
- 已更正：Ghidra 產生的 caller C 漏了第三個輸出結構參數；ARM64 x2 與唯讀分析型別修正結果支持三參數。
- JNI 仍維持 214＝197 靜態符號＋15 已核靜態註冊路徑＋2 未解；新 caller／buffer 邊界沒有被當作 runtime binding 證明。
- 先前韌體下載／ZIP 選檔／短讀／HTTP body／ACK 邊界沿用，不改稱已找到韌體解碼器。
- **停止點：A／B／C 中期提交後等待審查，不展開 D／E／F／G 全面分析。** 這是交付節點，不是 A／B／C 全部語義已完成。

## 續作規則

先讀 README、COVERAGE、UNRESOLVED 與 REPRODUCE；從具體未解函式或資源缺口續作，不重跑既有全方法／全符號掃描。所有原件只讀、不執行、不上傳，不連接相機或呼叫 App 遠端服務。公開 Git 僅保存自寫腳本、結構 metadata、報告與必要精簡證據；完整反編譯、SQLite 及工具留在忽略目錄。交付一致性由 `verify_delivery.py` 核對，帶本機樣本的收尾核查由 `scripts/verify_checkpoint.py` 執行。
