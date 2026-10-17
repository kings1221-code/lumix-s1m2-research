import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
/** Exact target functions (or function containing a proven BL), no callee expansion. */
public class ExportExact extends GhidraScript {
 public void run()throws Exception {
  long base=currentProgram.getImageBase().getOffset();String[] a=getScriptArgs();
  Set<Function> chosen=new LinkedHashSet<>();List<Object> missing=new ArrayList<>();
  for(String line:Files.readAllLines(Path.of(a[1]))) {
   String[] q=line.split("\\|");if(!q[0].equals(currentProgram.getName()))continue;
   Function f=getFunctionContaining(toAddr(base+Long.decode(q[1])));
   if(f==null)missing.add(line);else chosen.add(f);
  }
  DecompInterface d=new DecompInterface();d.openProgram(currentProgram);List<Object> output=new ArrayList<>();
  for(Function f:chosen) {
   Map<String,Object> r=new LinkedHashMap<>();r.put("name",f.getName());r.put("elf_va",String.format("0x%x",f.getEntryPoint().getOffset()-base));
   List<Object> blocks=new ArrayList<>(),instructions=new ArrayList<>(),callers=new ArrayList<>(),callees=new ArrayList<>();
   BasicBlockModel model=new BasicBlockModel(currentProgram);CodeBlockIterator bs=model.getCodeBlocksContaining(f.getBody(),monitor);
   while(bs.hasNext()) {
    CodeBlock b=bs.next();List<Object> edges=new ArrayList<>();CodeBlockReferenceIterator ds=b.getDestinations(monitor);
    while(ds.hasNext()){CodeBlockReference edge=ds.next();edges.add(Map.of("destination",edge.getDestinationAddress().toString(),"type",edge.getFlowType().toString()));}
    blocks.add(Map.of("start",b.getFirstStartAddress().toString(),"edges",edges));
   }
   InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
   while(it.hasNext()){Instruction i=it.next();instructions.add(Map.of("address",i.getAddress().toString(),"instruction",i.toString(),"bytes",ghidra.util.NumericUtilities.convertBytesToString(i.getBytes())));}
   for(Function g:f.getCallingFunctions(monitor))callers.add(Map.of("name",g.getName(),"entry",g.getEntryPoint().toString()));
   for(Function g:f.getCalledFunctions(monitor))callees.add(Map.of("name",g.getName(),"entry",g.getEntryPoint().toString(),"external",g.isExternal(),"thunk",g.isThunk()));
   DecompileResults dec=d.decompileFunction(f,45,monitor);r.put("decompile_completed",dec.decompileCompleted());r.put("error",dec.getErrorMessage());
   if(dec.decompileCompleted())r.put("c",dec.getDecompiledFunction().getC());
   r.put("blocks",blocks);r.put("instructions",instructions);r.put("callers",callers);r.put("callees",callees);output.add(r);
  }
  d.dispose();Path dir=Path.of(a[0]);Files.createDirectories(dir);
  Files.writeString(dir.resolve(currentProgram.getName()+".json"),new GsonBuilder().setPrettyPrinting().create().toJson(Map.of("library",currentProgram.getName(),"image_base",base,"functions",output,"missing",missing,"target_execution",false)),StandardOpenOption.CREATE_NEW);
 }
}
