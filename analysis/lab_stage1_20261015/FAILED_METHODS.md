# JADX 1.5.6 失敗方法核對

42 錯誤事件對應 24 個不同方法。全部已恢復原始指令與結構 CFG；未把 CFG 有效等同完整高階語義恢復。

| Raw DEX 方法 | DEX / code_item | Code units | 事件數 | 修復界線 |
|---|---|---:|---:|---|
| `LB9/o;->j(LB9/q;)LB9/q;` | classes2.dex / `0xe93e8` | 310 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `LB9/x;->a(LB9/y;)LB9/y;` | classes2.dex / `0xebe80` | 522 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `LC0/Q;->w(Landroid/net/Uri;Ljava/lang/String;)I` | classes.dex / `0x188534` | 320 | 1 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `LF0/b0;->m(Lz0/B0;Z)V` | classes.dex / `0x1b4a88` | 992 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `LH0/H;->c()Z` | classes.dex / `0x1cc7ac` | 62 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `LJ0/F;->f(LJ0/z;LJ0/B;)Ljava/util/ArrayList;` | classes.dex / `0x1e7240` | 382 | 1 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `LJ2/y;->a(LK2/f;)Ly2/l;` | classes.dex / `0x1ec49c` | 1022 | 1 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `LX7/u;->a(LX7/d;LE7/c;)Ljava/lang/Object;` | classes2.dex / `0x1af5c4` | 288 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `La0/q;->r(Ljava/lang/Object;)Ljava/lang/Object;` | classes.dex / `0x25f334` | 452 | 1 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Landroidx/coordinatorlayout/widget/CoordinatorLayout;->u()V` | classes.dex / `0x285e00` | 392 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lcom/google/android/gms/internal/auth/zzga;->zzb(Ljava/lang/Object;[BIIILcom/google/android/gms/internal/auth/zzdt;)I` | classes.dex / `0x39b1a8` | 3938 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lcom/google/common/collect/X;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;` | classes.dex / `0x41fdf4` | 399 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lcom/google/common/collect/b1;-><init>(Lcom/google/common/collect/b1;)V` | classes.dex / `0x4244f0` | 49 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lcom/panasonic/jp/lumixlab/controller/activity/MainActivity;->a0(Lcom/panasonic/jp/lumixlab/controller/activity/MainActivity;ZLandroid/net/Uri;)V` | classes2.dex / `0x1e4480` | 1377 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lcom/panasonic/jp/lumixlab/controller/activity/RemoteShootingActivity;->Y0(LK5/Q0;)V` | classes2.dex / `0x1f1d14` | 9050 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lcom/panasonic/jp/lumixlab/util/v;->Q(Ljava/io/BufferedReader;Lcom/panasonic/jp/lumixlab/bean/EditLutListBean;)V` | classes2.dex / `0x235fb8` | 1012 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lf5/r1;->a()V` | classes2.dex / `0x2c12e0` | 1046 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lj5/C;->a(Lj5/C;JIFLE7/c;)Ljava/lang/Object;` | classes2.dex / `0x32a50c` | 538 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Ll0/h;->D(Ljava/io/BufferedInputStream;Ljava/io/BufferedOutputStream;)V` | classes.dex / `0x49c810` | 199 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Ll0/h;->e(Ll0/b;II)V` | classes.dex / `0x49a8a0` | 478 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Ln1/a;->j([BIZ)Ll1/d;` | classes.dex / `0x4a9bc4` | 1030 | 1 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lp6/k;->r(Ljava/lang/Object;)Ljava/lang/Object;` | classes2.dex / `0x36120c` | 1226 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lr1/f;->p(Lorg/xmlpull/v1/XmlPullParser;Ljava/util/HashMap;Lr1/c;Lr1/e;Ljava/util/HashMap;Ljava/util/HashMap;)V` | classes.dex / `0x4bf21c` | 638 | 1 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
| `Lx/i;->c(Lt/d;Z)V` | classes.dex / `0x4ebd08` | 2056 | 2 | 原始指令／CFG 已恢復；完整語義仍待覆核 |
