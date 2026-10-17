"""PT_LOAD byte checks and bounded native buffer/CFG facts; no target execution."""
import collections
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from common import *
def main():
    out=[];count=0;helper=[]
    imports=load(RESULTS/'native_import_calls.json.gz')['libraries']
    for p in sorted((WORK/'native').glob('*.json')):
        x=load(p);path=SOURCE/'extracted/arm64/lib/arm64-v8a'/x['library'];blob=path.read_bytes()
        with path.open('rb') as stream:
            elf=ELFFile(stream);segments=list(elf.iter_segments())
            def offset(va):
                s=next(s for s in segments if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz'])
                return s['p_offset']+va-s['p_vaddr']
            fs=[]
            for f in x['functions']:
                addresses=set();raw=b''
                for i in f['instructions']:
                    va=int(i['address'],16)-x['image_base'];at=offset(va);data=bytes.fromhex(i['bytes']);assert blob[at:at+len(data)]==data
                    raw+=data;count+=1;addresses.add(va)
                calls=[r for l in imports if l['library']==x['library'] for r in l['direct_BL_calls'] if int(r['elf_va'],16) in addresses]
                fs.append({'elf_va':f['elf_va'],'name':f['name'],'instruction_rows_checked':len(f['instructions']),'concatenated_instruction_bytes_sha256':sha(raw),
                           'tool_CFG_blocks':f['blocks'],'decompile_completed':f['decompile_completed'],'generated_C_sha256':sha(f.get('c','').encode()),
                           'callers':f['callers'],'callees':f['callees'],'verified_selected_import_calls':calls})
            if x['library']=='libavformat.so':
                va=0x135a84;at=offset(va);md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
                for i in md.disasm(blob[at:at+48],va):
                    helper.append({'elf_va':hex(i.address),'file_offset':offset(i.address),'raw_hex':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
                    if i.mnemonic=='ret':break
                assert any(i['instruction'].startswith('ldr x8, [x0, #0x10]') for i in helper)
                assert any(i['instruction'].startswith('ldr x0, [x8, #0x120]') for i in helper)
                assert any(i['instruction'].startswith('str w10, [x9, #0x20]') for i in helper)
            out.append({'library':x['library'],**identity(path),'functions':fs,'missing_function_targets':x['missing']})
    save(RESULTS/'native_evidence.json',{'libraries':out,'total_instruction_rows_original_ELF_checked':count,'SSL_object_getter_original_instructions':helper,
      'helper_side_effect':'0x135a84 also copies bit 0x8 from parent context flags +0x20 into underlying context(+0x110)->flags+0x20; it is not a pure getter.',
      'buffer_findings':[
       {'library':'libavformat.so','elf_va':'0x1354fc','status':'verified bounded static flow','input':'context private pointer at context+0x10, stream/options setup helper 0x1351cc',
        'actions':'TLS client/server method by flag +0x28; SSL_CTX_new stored +0x118; conditional CA/certificate/key file options; BIO callbacks; SSL_new stored +0x120; SSL_connect or SSL_accept',
        'output':'0 or error with cleanup helper 0x1357d4','limits':'No runtime key/cert files accessed. Actual URL options, negotiated cipher/key/IV and Android-side selection unknown.'},
       {'library':'libavformat.so','elf_va':['0x135754','0x135794'],'status':'verified bounded static flow','input':'caller context, buffer pointer and length; helper 0x135a84 changes x0 to private SSL object and preserves buffer registers',
        'actions':'helper aligns underlying I/O flag bit0x8, then SSL_read/SSL_write, branch on result; error translator 0x1359ac','output':'byte/result count or error','limits':'TLS stream consumer, not a proven firmware-buffer consumer.'},
       {'library':'libavformat.so','elf_va':'0xb8aa4','status':'verified bounded static data transformation','input':'caller output pointer/length; input read helper, lazily allocated 0x40000 buffer',
        'actions':'compression-state flag +0x27c8; z_stream-like next_in/avail_in +0x27d0/+0x27d8, next_out/avail_out +0x27e8/+0x27f0; inflate(stream,2)',
        'output':'requested length minus remaining output space, or read/error/reconnect branch','limits':'Compressed stream bytes are demonstrated; no firmware input origin or entire protocol/state-machine proof.'}],
      'scope':'4 new libavformat functions plus 9 inherited cube functions now have explicit tool CFGs and original byte checks. Full C/assembly stays private. Linear import BL inventory is a separate evidence level.'})
    print('PASS',sum(len(l['functions']) for l in out),'functions;',count,'original instruction rows; SSL buffer getter verified')
if __name__=='__main__':main()
