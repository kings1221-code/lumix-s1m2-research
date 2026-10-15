import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

/** Local-only decompilation and instruction evidence; never executes analyzed programs. */
public class ExportStage1 extends GhidraScript {
 public void run() throws Exception {
  String[] a=getScriptArgs();Path output=Path.of(a[0]);Files.createDirectories(output);
  Set<Long> extra=new HashSet<>();
  if(a.length>1)for(String line:Files.readAllLines(Path.of(a[1]))){String[] p=line.split("\\|");if(p.length==2&&p[0].equals(currentProgram.getName()))extra.add(Long.decode(p[1]));}
  long base=currentProgram.getImageBase().getOffset();
  for(long va:extra){Address address=toAddr(base+va);if(getFunctionAt(address)==null){disassemble(address);createFunction(address,null);}}
  DecompInterface decomp=new DecompInterface();decomp.openProgram(currentProgram);
  List<Object> functions=new ArrayList<>();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true)){
   boolean select=extra.contains(f.getEntryPoint().getOffset()-base)||f.getName().equals("JNI_OnLoad")||
    (currentProgram.getName().equals("libllc.so")&&f.getName().startsWith("Java_"));
   if(!select)continue;
   Map<String,Object> row=new LinkedHashMap<>();row.put("name",f.getName());row.put("entry",f.getEntryPoint().toString());row.put("elf_va",String.format("0x%x",f.getEntryPoint().getOffset()-base));row.put("body_bytes",f.getBody().getNumAddresses());
   List<Object> instructions=new ArrayList<>(),calls=new ArrayList<>();
   InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
   while(it.hasNext()){
    Instruction i=it.next();List<Object> refs=new ArrayList<>();
    for(Reference r:i.getReferencesFrom())refs.add(Map.of("to",r.getToAddress().toString(),"type",r.getReferenceType().toString()));
    instructions.add(Map.of("address",i.getAddress().toString(),"instruction",i.toString(),"bytes",ghidra.util.NumericUtilities.convertBytesToString(i.getBytes()),"references",refs));
    if(i.getFlowType().isCall())calls.add(Map.of("address",i.getAddress().toString(),"instruction",i.toString(),"references",refs));
   }
   DecompileResults result=decomp.decompileFunction(f,45,monitor);row.put("decompile_completed",result.decompileCompleted());row.put("error",result.getErrorMessage());
   if(result.decompileCompleted())row.put("c",result.getDecompiledFunction().getC());
   row.put("instructions",instructions);row.put("calls",calls);functions.add(row);
  }
  decomp.dispose();
  Map<String,Object> result=new LinkedHashMap<>();result.put("program",currentProgram.getName());result.put("language",currentProgram.getLanguageID().toString());result.put("image_base",currentProgram.getImageBase().toString());result.put("mapping","Ghidra address = original ELF virtual address + image_base (original PT_LOAD base 0)");result.put("target_executed",false);result.put("functions",functions);
  Files.writeString(output.resolve(currentProgram.getName()+".json"),new GsonBuilder().setPrettyPrinting().create().toJson(result));
  println("STAGE1 exported "+functions.size()+" selected functions from "+currentProgram.getName());
 }
}
