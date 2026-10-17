"""Explicit producer/finite-set checks outside the local literal propagator."""
from common import *
from dynamic import flow
def main():
    raw={m['method']:m for p in ('instructions.jsonl','extra_instructions.jsonl','review_instructions.jsonl') for m in rows(WORK/p)}
    ff=raw['Lwseemann/media/FFmpegMediaMetadataRetriever;-><clinit>()V'];by={i['offset_cu']:i for i in ff['instructions']};s=flow(ff)[14]
    libs=[s[r][1] for r in by[14]['registers']];assert libs==['crypto','ssl','avutil','swscale','avcodec','avformat','ffmpeg_mediametadataretriever_jni']
    assert by[24]['opcode']=='aget-object' and by[26]['reference']=='Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V'
    assert by[29]['literal']==1 and by[31]['target_cu']==22 and by[22]['target_cu']==32
    assert by[32]['reference'].endswith('->native_init()V')
    room=next(m for m in raw.values() if m['method'].startswith('Lcom/panasonic/jp/lumixlab/database/AppDatabase;->p('));ri={i['offset_cu']:i for i in room['instructions']}
    assert ri[24]['reference']=='Lcom/panasonic/jp/lumixlab/database/AppDatabase;'
    assert ri[312]['reference']=='LD1/Q;->b:Ljava/lang/Class;' and ri[374]['reference']=='_Impl'
    ctor=raw['LD1/Q;-><init>(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)V']
    stores=[i for i in ctor['instructions'] if i.get('reference')=='LD1/Q;->b:Ljava/lang/Class;'];assert len(stores)==1 and stores[0]['opcode']=='iput-object'
    exists=any(m['method'].startswith('Lcom/panasonic/jp/lumixlab/database/AppDatabase_Impl;->') for m in methods());assert exists
    handler=raw['Loa/t0;->invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;']
    hi={i['offset_cu']:i for i in handler['instructions']};assert hi[8]['reference'].startswith('Ljava/lang/reflect/Method;->invoke')
    assert any(i.get('reference')=='Ljava/lang/Object;' for i in handler['instructions'] if i['opcode']=='const-class')
    assert hi[0x47]['reference']=='Loa/v0;->c(Ljava/lang/reflect/Method;)Loa/w0;' and hi[0x4b]['reference']=='Loa/w0;->a([Ljava/lang/Object;)Ljava/lang/Object;'
    factory=raw['Loa/v0;->b()Ljava/lang/Object;'];assert any(c['reference'].startswith('Ljava/lang/reflect/Proxy;->newProxyInstance') for c in factory['calls'])
    save(RESULTS/'dynamic_manual_checks.json',{'finite_native_load_set':{'method':ff['method'],'site_cu':26,'array_cu':14,'load_order':libs,'loop_test_cu':22,'native_init_cu':32,
      'status':'verified Java finite-set load loop; actual successful native loading not tested'},
      'room_generated_target':{'method':room['method'],'site_cu':410,'class_literal_cu':24,'builder_field_read_cu':312,'builder_constructor':ctor['method'],
       'builder_store_cu':stores[0]['offset_cu'],'candidate':'com.panasonic.jp.lumixlab.database.AppDatabase_Impl','class_present_in_DEX':exists,
       'status':'reasonable inference for normally initialized builder; interprocedural mutable-field proof not complete, excluded from exact-resolution count'},
      'retrofit_dispatch':{'factory':factory['method'],'factory_proxy_cu':138,'handler':handler['method'],
       'Object_method_reflection_cu':8,'normal_service_parse_cu':71,'normal_service_execute_cu':75,
       'verified':'Object-declared methods use reflective invoke; default methods use MethodHandle/constructor compatibility route; ordinary service methods go to v0.c(Method) -> w0.a(arguments). Interface annotations/body consumers are inherited evidence, no APK execution.',
       'limits':'Not full restoration of every converter, adapter, interceptor or dynamic provider.'},
      'resolution_accounting':{'original_denominator':243,'CFG_exact_literal_targets':95,'additional_verified_finite_set_sites':1,'bounded_target_total':96,'remaining_not_exact_or_finite':147,'runtime_execution_proofs':0}})
    print('PASS 7-library finite load loop; Room producer candidate; Retrofit proxy/default/Object/service split')
if __name__=='__main__':main()
