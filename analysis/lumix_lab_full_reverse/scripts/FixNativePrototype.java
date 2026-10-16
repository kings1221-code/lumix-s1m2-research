import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
/** Read-only project run: correct one analysis signature proven by x0/x1/x2 instructions. */
public class FixNativePrototype extends GhidraScript {
 public void run()throws Exception {
  long base=currentProgram.getImageBase().getOffset();
  Function callee=getFunctionAt(toAddr(base+0x4e60));
  Function caller=getFunctionAt(toAddr(base+0x51d0));
  DataType ptr=new PointerDataType(VoidDataType.dataType,8,currentProgram.getDataTypeManager());
  callee.setReturnType(VoidDataType.dataType,SourceType.USER_DEFINED);
  callee.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,
    new ParameterImpl("input1",ptr,currentProgram),new ParameterImpl("input2",ptr,currentProgram),new ParameterImpl("output",ptr,currentProgram));
  DecompInterface d=new DecompInterface();d.openProgram(currentProgram);d.flushCache();
  DecompileResults r=d.decompileFunction(caller,60,monitor);
  if(!r.decompileCompleted())throw new Exception(r.getErrorMessage());
  Path p=Path.of(getScriptArgs()[0]);Files.createDirectories(p);
  Files.writeString(p.resolve("prototype_fixed.json"),new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
    "library",currentProgram.getName(),"caller_elf_va","0x51d0","callee_elf_va","0x4e60",
    "signature",callee.getSignature().toString(),"c",r.getDecompiledFunction().getC(),
    "scope","Analysis-only 3-pointer signature; run with -readOnly; target file unchanged")),StandardOpenOption.CREATE_NEW);
  d.dispose();
 }
}
