import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.Gson;
import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.reference.*;
import com.android.tools.smali.dexlib2.iface.value.*;

/** Parses DEX as data with the official JADX-bundled dexlib2. Never loads target classes. */
public class DexIndex {
 static String id(MethodReference m) {
  StringBuilder s=new StringBuilder(m.getDefiningClass()+"->"+m.getName()+"(");
  for(CharSequence p:m.getParameterTypes())s.append(p);
  return s.append(")").append(m.getReturnType()).toString();
 }
 static String ref(Reference r) {
  if(r instanceof MethodReference)return id((MethodReference)r);
  if(r instanceof StringReference)return ((StringReference)r).getString();
  if(r instanceof TypeReference)return ((TypeReference)r).getType();
  if(r instanceof FieldReference){FieldReference f=(FieldReference)r;return f.getDefiningClass()+"->"+f.getName()+":"+f.getType();}
  return r.toString();
 }
 static List<Integer> regs(Instruction i){
  List<Integer> r=new ArrayList<>();
  if(i instanceof FiveRegisterInstruction){FiveRegisterInstruction x=(FiveRegisterInstruction)i;int[] v={x.getRegisterC(),x.getRegisterD(),x.getRegisterE(),x.getRegisterF(),x.getRegisterG()};for(int k=0;k<x.getRegisterCount();k++)r.add(v[k]);}
  else if(i instanceof RegisterRangeInstruction){RegisterRangeInstruction x=(RegisterRangeInstruction)i;for(int k=0;k<x.getRegisterCount();k++)r.add(x.getStartRegister()+k);}
  else if(i instanceof ThreeRegisterInstruction){ThreeRegisterInstruction x=(ThreeRegisterInstruction)i;r.add(x.getRegisterA());r.add(x.getRegisterB());r.add(x.getRegisterC());}
  else if(i instanceof TwoRegisterInstruction){TwoRegisterInstruction x=(TwoRegisterInstruction)i;r.add(x.getRegisterA());r.add(x.getRegisterB());}
  else if(i instanceof OneRegisterInstruction)r.add(((OneRegisterInstruction)i).getRegisterA());
  return r;
 }
 public static void main(String[] args)throws Exception {
  boolean dump=args[0].equals("dump");int start=dump?3:2;
  Set<String> targets=dump?new HashSet<>(Files.readAllLines(Path.of(args[2]))):Set.of();
  Gson gson=new Gson();long count=0;
  try(BufferedWriter out=Files.newBufferedWriter(Path.of(args[1]))){
   for(int a=start;a<args.length;a++){
    DexFile dex=DexFileFactory.loadDexFile(new File(args[a]),Opcodes.getDefault());
    for(ClassDef c:dex.getClasses())for(Method m:c.getMethods()){
     String name=id(m);if(dump&&!targets.contains(name))continue;
     Map<String,Object> row=new LinkedHashMap<>();row.put("dex",Path.of(args[a]).getFileName().toString());row.put("method",name);row.put("access_flags",m.getAccessFlags());
     row.put("native",(m.getAccessFlags()&0x100)!=0);row.put("superclass",c.getSuperclass());
     List<Object> annotations=new ArrayList<>();for(Annotation an:m.getAnnotations()){Map<String,Object> values=new LinkedHashMap<>();for(AnnotationElement e:an.getElements()){EncodedValue v=e.getValue();values.put(e.getName(),v instanceof StringEncodedValue?((StringEncodedValue)v).getValue():v.toString());}annotations.add(Map.of("type",an.getType(),"values",values));}row.put("annotations",annotations);
     List<Object> calls=new ArrayList<>(),strings=new ArrayList<>(),instructions=new ArrayList<>();
     MethodImplementation impl=m.getImplementation();int off=0;
     if(impl!=null){row.put("registers",impl.getRegisterCount());
      for(Instruction i:impl.getInstructions()){
       Map<String,Object> ins=new LinkedHashMap<>();ins.put("offset_cu",off);ins.put("opcode",i.getOpcode().name);ins.put("registers",regs(i));ins.put("width_cu",i.getCodeUnits());
       if(i instanceof ReferenceInstruction){Reference r=((ReferenceInstruction)i).getReference();ins.put("reference",ref(r));
        if(i.getOpcode().name.startsWith("invoke-")&&r instanceof MethodReference)calls.add(ins);
        if(r instanceof StringReference)strings.add(Map.of("offset_cu",off,"registers",regs(i),"value",((StringReference)r).getString()));}
       if(i instanceof OffsetInstruction)ins.put("target_cu",off+((OffsetInstruction)i).getCodeOffset());
       if(i instanceof NarrowLiteralInstruction)ins.put("literal",((NarrowLiteralInstruction)i).getNarrowLiteral());
       else if(i instanceof WideLiteralInstruction)ins.put("literal",((WideLiteralInstruction)i).getWideLiteral());
       if(i instanceof SwitchPayload){List<Object> elements=new ArrayList<>();for(SwitchElement e:((SwitchPayload)i).getSwitchElements())elements.add(Map.of("key",e.getKey(),"relative_target_cu",e.getOffset()));ins.put("switch_elements",elements);}
       if(dump)instructions.add(ins);off+=i.getCodeUnits();
      }
      if(dump){List<Object> tries=new ArrayList<>();for(TryBlock<? extends ExceptionHandler> t:impl.getTryBlocks()){List<Object> hs=new ArrayList<>();for(ExceptionHandler h:t.getExceptionHandlers()){Map<String,Object>x=new LinkedHashMap<>();x.put("type",h.getExceptionType());x.put("target_cu",h.getHandlerCodeAddress());hs.add(x);}tries.add(Map.of("start_cu",t.getStartCodeAddress(),"count_cu",t.getCodeUnitCount(),"handlers",hs));}row.put("try_blocks",tries);}
     }
     row.put("code_units",off);row.put("calls",calls);row.put("strings",strings);if(dump)row.put("instructions",instructions);
     out.write(gson.toJson(row));out.newLine();count++;
    }
   }
  }
  System.out.println("Parsed methods: "+count+"; target code execution=false");
 }
}
