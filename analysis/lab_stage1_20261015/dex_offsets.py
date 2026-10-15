"""Independently parse DEX class_data/code_item offsets (no instruction interpretation)."""
import struct
def offsets(path):
 b=path.read_bytes()
 def u32(o):return struct.unpack_from('<I',b,o)[0]
 def uleb(o):
  n=0;s=0
  while True:
   x=b[o];o+=1;n|=(x&127)<<s
   if x<128:return n,o
   s+=7
 def string(o):
  _,o=uleb(o);return b[o:b.index(b'\0',o)].decode('utf-8',errors='replace')
 strings=[string(u32(u32(60)+4*i)) for i in range(u32(56))]
 types=[strings[u32(u32(68)+4*i)] for i in range(u32(64))]
 protos=[]
 for i in range(u32(72)):
  _,ret,params=struct.unpack_from('<III',b,u32(76)+12*i)
  ps=[types[struct.unpack_from('<H',b,params+4+2*j)[0]] for j in range(u32(params))] if params else []
  protos.append('('+''.join(ps)+')'+types[ret])
 methods=[]
 for i in range(u32(88)):
  c,p,n=struct.unpack_from('<HHI',b,u32(92)+8*i);methods.append(types[c]+'->'+strings[n]+protos[p])
 result={}
 for i in range(u32(96)):
  o=u32(u32(100)+32*i+24)
  if not o:continue
  counts=[]
  for _ in range(4):n,o=uleb(o);counts.append(n)
  for _ in range(sum(counts[:2])):_,o=uleb(o);_,o=uleb(o)
  for count in counts[2:]:
   index=0
   for _ in range(count):
    diff,o=uleb(o);flags,o=uleb(o);code,o=uleb(o);index+=diff
    result[methods[index]]={'method_index':index,'code_item_offset':code,'insns_offset':code+16 if code else None,
                            'code_units':u32(code+12) if code else 0,'access_flags':flags}
 return result
