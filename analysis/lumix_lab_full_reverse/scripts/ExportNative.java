import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
/** New selected functions + immediate native callees. Target never runs. */
public class ExportNative extends GhidraScript {
 public void run() throws Exception {
  String[] a=getScriptArgs();long base=currentProgram.getImageBase().getOffset();
  Set<Function> chosen=new LinkedHashSet<>();
  for(String line:Files.readAllLines(Path.of(a[1]))) {
   String[] p=line.split("\\|");if(!p[0].equals(currentProgram.getName()))continue;
   Function f=getFunctionAt(toAddr(base+Long.decode(p[1])));if(f!=null)chosen.add(f);
  }
  Set<Function> seeds=new LinkedHashSet<>(chosen);
  for(Function f:seeds)for(Function g:f.getCalledFunctions(monitor))if(!g.isExternal()&&!g.isThunk())chosen.add(g);
  List<Object> out=new ArrayList<>();DecompInterface d=new DecompInterface();d.openProgram(currentProgram);
  for(Function f:chosen) {
   Map<String,Object> r=new LinkedHashMap<>();r.put("name",f.getName());r.put("elf_va",String.format("0x%x",f.getEntryPoint().getOffset()-base));r.put("entry",f.getEntryPoint().toString());r.put("seed",seeds.contains(f));
   List<Object> callers=new ArrayList<>(),callees=new ArrayList<>(),ins=new ArrayList<>();
   for(Function c:f.getCallingFunctions(monitor))callers.add(Map.of("name",c.getName(),"entry",c.getEntryPoint().toString()));
   for(Function c:f.getCalledFunctions(monitor))callees.add(Map.of("name",c.getName(),"entry",c.getEntryPoint().toString(),"external",c.isExternal(),"thunk",c.isThunk()));
   InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
   while(it.hasNext()){Instruction i=it.next();ins.add(Map.of("address",i.getAddress().toString(),"instruction",i.toString(),"bytes",ghidra.util.NumericUtilities.convertBytesToString(i.getBytes())));}
   DecompileResults de=d.decompileFunction(f,40,monitor);r.put("decompile_completed",de.decompileCompleted());r.put("error",de.getErrorMessage());if(de.decompileCompleted())r.put("c",de.getDecompiledFunction().getC());
   r.put("callers",callers);r.put("callees",callees);r.put("instructions",ins);out.add(r);
  }
  d.dispose();Path p=Path.of(a[0]);Files.createDirectories(p);
  Files.writeString(p.resolve(currentProgram.getName()+".json"),new GsonBuilder().setPrettyPrinting().create().toJson(Map.of("library",currentProgram.getName(),"image_base",base,"identified_project_functions",currentProgram.getFunctionManager().getFunctionCount(),"functions",out,"target_execution",false)),StandardOpenOption.CREATE_NEW);
 }
}
