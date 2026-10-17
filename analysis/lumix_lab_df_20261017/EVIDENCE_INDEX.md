# 原始程式證據入口

所有方法屬 Lab 3.1.0／22；DEX SHA 於 INPUT_MANIFEST。CU 是方法指令起點的 16-bit code unit；file offset＝insns_offset＋2×CU。下面只是 reviewed Java 消費者，不是全部方法語義清單。

| 流程 ID／方法 | DEX | code_item / insns file offset | 指令區 SHA-256 |
|---|---|---|---|
| camera_peer_fingerprint<br>`Lh6/d;->verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z` | classes2.dex | `0x30c6f8` / `0x30c708` | `d85a982a3461e19a8914146a7fb306245600a3251160f9f070466a1b1f185dac` |
| filename_uint32<br>`Lcom/panasonic/jp/lumixlab/bean/RawProcessingConfigBean;->hashFileNameToUint32(Ljava/lang/String;)I` | classes2.dex | `0x1dab18` / `0x1dab28` | `45e995e90d0356ee56a5ecdf8ab806c22d6c68bff767c3080560160b368b42e6` |
| lottie_cache_filename<br>`LI2/f;->a(Ljava/lang/String;LI2/c;Z)Ljava/lang/String;` | classes.dex | `0x1dead8` / `0x1deae8` | `51bae81e9bd6b7fab98ac1354451442c470a2deab7241d1073fae5ee21dddbf8` |
| image_disk_cache_key<br>`LT2/u;->a(LP2/q;)Ljava/lang/String;` | classes.dex | `0x242100` / `0x242110` | `6482e9c955cb0ab538e680d139c2461de71763c2dc166c749b87db04f217d546` |
| firebase_legacy_installation_id<br>`LR4/d;->a()Ljava/lang/String;` | classes.dex | `0x237a6c` / `0x237a7c` | `10253b32bed0be5f10df9eb2c2811e88f83f5033ca7139fcef7295c7f77c92ea` |
| play_review_store_identity<br>`Lq4/k;-><init>(Landroid/content/Context;)V` | classes.dex | `0x4b99bc` / `0x4b99cc` | `3c434bc97183bd59c3afcfc006459d7b42a624aa865030d3e671c798f57067e6` |
| firebase_app_name_hash<br>`Lcom/google/firebase/messaging/GmsRpc;->getHashedFirebaseAppName()Ljava/lang/String;` | classes.dex | `0x42c4ec` / `0x42c4fc` | `f910beca0f322c51f10115ed383ae6d97b43249e91515c0b30181282133567e4` |
| adobe_string_hash<br>`Lcom/adobe/marketing/mobile/internal/util/i;->a(Ljava/lang/String;)Ljava/lang/String;` | classes.dex | `0x2f0ab4` / `0x2f0ac4` | `1625425393aa3ab5a875930a612fda66d77e3b28b6a42bcefc586da1652a27ec` |
| oauth_hmac_sha256<br>`Lcom/google/api/client/auth/oauth/OAuthHmacSha256Signer;->computeSignature(Ljava/lang/String;)Ljava/lang/String;` | classes.dex | `0x3c164c` / `0x3c165c` | `3d1e2e32ea5adab33b34f3cd3588d0c43d5d22b30f18f5c33ba36783ac0f27a8` |
| oauth_hmac_sha1<br>`Lcom/google/api/client/auth/oauth/OAuthHmacSigner;->computeSignature(Ljava/lang/String;)Ljava/lang/String;` | classes.dex | `0x3c1734` / `0x3c1744` | `8d08360cb799a4d34a7c4d28bf9b94870e6417018fdf41b579180405a91b9f94` |
| pkce_challenge<br>`Lcom/google/api/client/auth/oauth2/AuthorizationCodeFlow$PKCE;->generateChallenge(Ljava/lang/String;)V` | classes.dex | `0x3c23ec` / `0x3c23fc` | `6ec773a12b9a32897fe33f18fdd1909f5a28726af0fca42d295e2331f4d7e0e2` |
| community_zip<br>`Lcom/panasonic/jp/lumixlab/controller/fragment/CommunityDownloadFragment;->o0(Lcom/panasonic/jp/lumixlab/controller/fragment/CommunityDownloadFragment;Ljava/lang/String;Ljava/io/File;Ljava/lang/String;)V` | classes2.dex | `0x212aa0` / `0x212ab0` | `7f75587adc415571db4d31186ad4d2e1e28e4191a68829e8d71e1ada4132acf9` |
| http_basic_encoding<br>`Lh6/h;->j()Lg8/s0;` | classes2.dex | `0x30cdb4` / `0x30cdc4` | `e2b9c6a9182dc246d2cadf77e5cf390fe28b2338a835638f98c7d31f34027aa1` |
| printable_ascii_filter<br>`LI5/d;->a([B)Ljava/lang/String;` | classes2.dex | `0x15c950` / `0x15c960` | `b9c591d8cd3daf43994f7ea7b720d22d9a4674d07748a5968e230831cc281fa9` |

全部 2231 個定點方法 location／SHA、11280 個原 invoke operands、591 個動態字串 ID operands 在 results/selected_dex_evidence.json.gz。字串原值不散布。

原生四個新函式、九個 cube CFG、caller／callee、各條 import BL 的 file offset／bytes 在 native_evidence.json／native_import_calls.json.gz；原始指令全文和 C 留在私有 WORK。
