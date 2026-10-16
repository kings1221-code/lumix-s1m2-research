# INPUT_MANIFEST：Lab 3.1.0／22

【已驗證】本輪重核以下 25 個原始檔。來源沿用合法取得的 Google Play delivery 記錄，沒有新做 publisher signature 信任鏈；不把歷史鏡像的 XAPK／缺失 split 混入。原件不修改／執行／上傳。

| 類別／檔案或 APK 成員 | bytes | SHA-256 |
|---|---:|---|
| APK `com.panasonic.jp.lumixlab-22.apk` | 189845077 | `6ba873110d201675a905f7dac39bcda3291674e7440a484d6d5bd1a78447115f` |
| APK `com.panasonic.jp.lumixlab-22-config.arm64_v8a.apk` | 42944168 | `4e1a4fcbb9321bacfce69b6719146b5f8b249d5d9dded72044d23b99903fcdb4` |
| APK `com.panasonic.jp.lumixlab-22-config.en.apk` | 78233 | `6288e4ea41dce76389814d191eb39afed7a5171d8f80116612c0f23fe98e6ca5` |
| APK `com.panasonic.jp.lumixlab-22-config.xxhdpi.apk` | 9983302 | `6b62ec477edfa3673b87c7f361721fb4707a3c2d313d45c70ada1c8774515b39` |
| APK `com.panasonic.jp.lumixlab-22-config.zh.apk` | 205209 | `626fab49109927bba388a81370b80d509717424033a7caedfb7b96e2557ca18f` |
| DEX `classes.dex` | 7341852 | `02782fe6cf962788d1e5e76f707fc9d5e45669c205eaafee9bb8c50f2f5810ff` |
| DEX `classes2.dex` | 5047724 | `4147c194d9814bac0f83e2120705b6e03524a3425d2492eafdbf547898736552` |
| ELF_ARM64 `lib/arm64-v8a/libavcodec.so` | 7377464 | `4bcd087282fe141181be4cb770218d94f1f924f2a99a6770ce36a91d22d1e9aa` |
| ELF_ARM64 `lib/arm64-v8a/libavformat.so` | 1461856 | `4d364b5e2855c8e828eb02474c3cec47b8801f88a59c8625dc64a260604eaa79` |
| ELF_ARM64 `lib/arm64-v8a/libavutil.so` | 491368 | `3676eb0ed26d540287ab8470c8abe618153afc45258451298b5d4ffd18ff010b` |
| ELF_ARM64 `lib/arm64-v8a/libc++_shared.so` | 1374336 | `c4c2fe5cbcb1fba0003a31fc7ab29a9bb12df6cc187ec45a806462540e83d93b` |
| ELF_ARM64 `lib/arm64-v8a/libcrypto.so` | 2676640 | `49db5bf9fdee2c87209085717497ac604b8768d589df32a85d8124c3f7604b4a` |
| ELF_ARM64 `lib/arm64-v8a/libcube_merge.so` | 11976 | `91c35f56413f0e6fd8108000104a4270b6beee64121bfd954ada56e510c03d2f` |
| ELF_ARM64 `lib/arm64-v8a/libde265.so` | 1329336 | `546563ccbc766ed8015a980d163e85af52af54f2eb193e1bb2e7471f04970d58` |
| ELF_ARM64 `lib/arm64-v8a/libffmpeg_mediametadataretriever_jni.so` | 58720 | `dfd412e3103b203ed96adbbf30e2c70053afdeaf172c1a5cc9a8b849ff9ee471` |
| ELF_ARM64 `lib/arm64-v8a/libheif.so` | 994704 | `e229d1a052a48ceb6defe47570ee6a448bf3c461205132580e4a52c961df8e83` |
| ELF_ARM64 `lib/arm64-v8a/libllc.so` | 104008 | `7433d705215bb92e7a87b9005277127e5851c7a4638ca8f6a3db17d2a00927df` |
| ELF_ARM64 `lib/arm64-v8a/libonnxruntime.so` | 18214224 | `3fc3e79539f06f67360a810e60eb5c513db5febc16f7bc71e5d9e8ce39e3d775` |
| ELF_ARM64 `lib/arm64-v8a/libonnxruntime4j_jni.so` | 75720 | `adcaf5e11ff65ad7b54725b2869118568b14ce2f3596d1b6f082ed0c774f2539` |
| ELF_ARM64 `lib/arm64-v8a/libssl.so` | 590168 | `f8be5421e9186804504bd4f74e76fe23b71af401d311b559479500f227fd24ec` |
| ELF_ARM64 `lib/arm64-v8a/libswscale.so` | 350224 | `f381b19a9947ac25acb95e91c539ff31c634fca2ca70939b4bb8afb36c85b581` |
| ELF_ARM64 `lib/arm64-v8a/libtechorfilter.so` | 6340624 | `03e1c4e11e86012e03faf025fd566be79df3fc75ee28d38433d676a959b3d25f` |
| ELF_ARM64 `lib/arm64-v8a/libyuv-decoder.so` | 6216 | `ed3709f2b4b425746befbc6c6aab2235446ecbb37a33647b030828d8c6688dcf` |
| ELF_ARM64 `lib/arm64-v8a/libyuv.so` | 403888 | `987926e77bddb9880e16dfb11201d6fb0429c4ff462a74e0bd0965b3de4d85c3` |
| ELF_ARM64 `lib/arm64-v8a/libyuv_android.so` | 899360 | `dab061cb65b5b86318c5a01b2c47ac6da7da064421a5c9ef71b71123b0df5809` |

檔案位置以 `<SOURCE_ROOT>/apk/`、`extracted/base/`、`extracted/arm64/` 指示；本機精確根位置只在忽略的 local_paths.json。五個 APK 所有成員另有 [apk_members.json.gz](results/apk_members.json.gz)。只對這個樣本目錄作核驗，不宣稱已搜遍電腦或不存在其他 App 版本。
