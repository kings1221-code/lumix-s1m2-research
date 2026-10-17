# 其餘 23 個失敗方法的審閱排序

42 次歷史 error／24 個不同方法維持原證據。以下不含已補部分 PNG 語義的 D；**所有 23 項仍未新增完整高階語義**。分數只用 direct file/security/network/reflection/JNI 等引用與 App 入口權重，CU 代表成本。分數 0 不表示安全或沒有功能。

| 順序 | 分數 | 原方法 | DEX／code_item | CU | direct evidence 類別 |
|---:|---:|---|---|---:|---|
| 1 | 15 | `Lcom/panasonic/jp/lumixlab/util/v;->Q(Ljava/io/BufferedReader;Lcom/panasonic/jp/lumixlab/bean/EditLutListBean;)V` | classes2.dex / `0x235fb8` | 1012 | file_IO |
| 2 | 14 | `Lcom/panasonic/jp/lumixlab/controller/activity/MainActivity;->a0(Lcom/panasonic/jp/lumixlab/controller/activity/MainActivity;ZLandroid/net/Uri;)V` | classes2.dex / `0x1e4480` | 1377 | file_IO |
| 3 | 8 | `Lcom/panasonic/jp/lumixlab/controller/activity/RemoteShootingActivity;->Y0(LK5/Q0;)V` | classes2.dex / `0x1f1d14` | 9050 | 未由指定 direct 模式分類 |
| 4 | 6 | `Ll0/h;->e(Ll0/b;II)V` | classes.dex / `0x49a8a0` | 478 | file_IO |
| 5 | 6 | `Lp6/k;->r(Ljava/lang/Object;)Ljava/lang/Object;` | classes2.dex / `0x36120c` | 1226 | file_IO |
| 6 | 0 | `Lcom/google/common/collect/b1;-><init>(Lcom/google/common/collect/b1;)V` | classes.dex / `0x4244f0` | 49 | 未由指定 direct 模式分類 |
| 7 | 0 | `LH0/H;->c()Z` | classes.dex / `0x1cc7ac` | 62 | 未由指定 direct 模式分類 |
| 8 | 0 | `LX7/u;->a(LX7/d;LE7/c;)Ljava/lang/Object;` | classes2.dex / `0x1af5c4` | 288 | 未由指定 direct 模式分類 |
| 9 | 0 | `LB9/o;->j(LB9/q;)LB9/q;` | classes2.dex / `0xe93e8` | 310 | 未由指定 direct 模式分類 |
| 10 | 0 | `LC0/Q;->w(Landroid/net/Uri;Ljava/lang/String;)I` | classes.dex / `0x188534` | 320 | 未由指定 direct 模式分類 |
| 11 | 0 | `LJ0/F;->f(LJ0/z;LJ0/B;)Ljava/util/ArrayList;` | classes.dex / `0x1e7240` | 382 | 未由指定 direct 模式分類 |
| 12 | 0 | `Landroidx/coordinatorlayout/widget/CoordinatorLayout;->u()V` | classes.dex / `0x285e00` | 392 | 未由指定 direct 模式分類 |
| 13 | 0 | `Lcom/google/common/collect/X;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;` | classes.dex / `0x41fdf4` | 399 | 未由指定 direct 模式分類 |
| 14 | 0 | `La0/q;->r(Ljava/lang/Object;)Ljava/lang/Object;` | classes.dex / `0x25f334` | 452 | 未由指定 direct 模式分類 |
| 15 | 0 | `LB9/x;->a(LB9/y;)LB9/y;` | classes2.dex / `0xebe80` | 522 | 未由指定 direct 模式分類 |
| 16 | 0 | `Lj5/C;->a(Lj5/C;JIFLE7/c;)Ljava/lang/Object;` | classes2.dex / `0x32a50c` | 538 | 未由指定 direct 模式分類 |
| 17 | 0 | `Lr1/f;->p(Lorg/xmlpull/v1/XmlPullParser;Ljava/util/HashMap;Lr1/c;Lr1/e;Ljava/util/HashMap;Ljava/util/HashMap;)V` | classes.dex / `0x4bf21c` | 638 | 未由指定 direct 模式分類 |
| 18 | 0 | `LF0/b0;->m(Lz0/B0;Z)V` | classes.dex / `0x1b4a88` | 992 | 未由指定 direct 模式分類 |
| 19 | 0 | `LJ2/y;->a(LK2/f;)Ly2/l;` | classes.dex / `0x1ec49c` | 1022 | 未由指定 direct 模式分類 |
| 20 | 0 | `Ln1/a;->j([BIZ)Ll1/d;` | classes.dex / `0x4a9bc4` | 1030 | 未由指定 direct 模式分類 |
| 21 | 0 | `Lf5/r1;->a()V` | classes2.dex / `0x2c12e0` | 1046 | 未由指定 direct 模式分類 |
| 22 | 0 | `Lx/i;->c(Lt/d;Z)V` | classes.dex / `0x4ebd08` | 2056 | 未由指定 direct 模式分類 |
| 23 | 0 | `Lcom/google/android/gms/internal/auth/zzga;->zzb(Ljava/lang/Object;[BIIILcom/google/android/gms/internal/auth/zzdt;)I` | classes.dex / `0x39b1a8` | 3938 | 未由指定 direct 模式分類 |
