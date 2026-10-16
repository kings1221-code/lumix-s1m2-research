# C：Java／JNI／Native 對照與兩個缺口

【已驗證】沿用兩個相同 SHA DEX、18 SO 的 214 宣告：197 靜態符號對照、15 有靜態 RegisterNatives 路徑、1 個 C++ 改名實作但綁定不明、1 個在 18 庫未找到綁定。FFmpeg 的 15 項登記表及 OnLoad 已在第一階段以 class／signature／table／count／JNITable slot 核過，不重跑。[原最終表](../lab_stage1_20261015/results/jni_mapping_verified.json)。

## splitYuvArrayToYAndUv

SO `libllc.so` SHA `7433d705215bb92e7a87b9005277127e5851c7a4638ca8f6a3db17d2a00927df`，ELF VA `0x16e18`。實際動態符號為 `_Z67Java_com_panasonic_jp_lumixlab_LlcApplication_splitYuvArrayToYAndUvP7_JNIEnvP8_jobjectP11_jbyteArrayS4_S4_ii`，不是普通 JNI short／long lookup 名稱。

【已驗證】函式對三個 byte[] 用 JNIEnv `+0x5c0` 取得元素；以寬×高產生 Y 區長度，memcpy 到第一輸出，從輸入後續區段呼叫 MergeUVPlane 寫第二輸出，再以 JNIEnv `+0x600` 釋放／回填。實際參數與負值右移／整數邊界仍以指令為準，不把 decompiler 型別當驗收。

【已驗證】本次 DEX 無可見直接 caller；已分析專案也沒有該入口的已識別直接 native caller。libllc 沒有已見 JNI_OnLoad、init-array section 或 DT_INIT／DT_INIT_ARRAY tag。**這些有限結果仍不能排除外部 RegisterNatives、dlsym、計算式或其他環境的入口**。【尚未確認】實際 runtime 綁定仍不成立，沒有因實作存在就把此項轉為「JNI 已驗證」。

## Google NativeOnCompleteListener

【已驗證】`createAndAddCallback(Task,long)` 建構 listener 並交給 Task.addOnCompleteListener；onComplete 根據 successful／cancelled／exception 建立 result 或 message，將 long handle、result、兩個 boolean、message 交給 nativeOnComplete。JADX、原 DEX 與選定 Baksmali 序列一致。

【已驗證】在這兩個 DEX 沒找到 createAndAddCallback 的顯式 caller；nativeOnComplete 的顯式 Java caller 是上述 onComplete。這 18 SO 的既有完整符號／候選表結果未建立實作綁定。【合理推論】它可能是可選 SDK native 整合入口；**未證明實際使用、也未證明永不使用**。外部 native producer、反射／optional module 或授權 runtime 證據缺失。

兩項完整新狀態與 caller 位置：[jni_unresolved_update.json](results/jni_unresolved_update.json)。這輪縮小了未知的具體邊界，沒有虛構兩項都已解決。

## 已接通的非 JNI 庫

`LlcApplication.mergeCubeFiles(String,String,String)I` → libllc `0x122ac` → import `cube_merge_files` → `libcube_merge.so:0x51d0`。libllc 的 DT_NEEDED 明列 libcube_merge.so；後者本身沒有 Java_* 或 JNI_OnLoad，仍有被使用的實際 native 呼叫證據。詳見 [ARM64 分析](ARM64_ANALYSIS.md)。
