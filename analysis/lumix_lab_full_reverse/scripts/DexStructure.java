import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.Gson;
import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.iface.*;
/** Read class/field metadata absent from stage1. Does not load target classes. */
public class DexStructure {
 public static void main(String[] args)throws Exception {
  Gson gson=new Gson();int count=0;
  try(BufferedWriter out=Files.newBufferedWriter(Path.of(args[0]),StandardOpenOption.CREATE_NEW)) {
   for(int a=1;a<args.length;a++) {
    DexFile dex=DexFileFactory.loadDexFile(new File(args[a]),Opcodes.getDefault());
    for(ClassDef c:dex.getClasses()) {
     Map<String,Object> row=new LinkedHashMap<>();
     row.put("dex",Path.of(args[a]).getFileName().toString());row.put("class",c.getType());
     row.put("superclass",c.getSuperclass());row.put("interfaces",c.getInterfaces());
     row.put("access_flags",c.getAccessFlags());row.put("source_file",c.getSourceFile());
     List<Object> fields=new ArrayList<>();
     for(Field f:c.getFields()) {
      Map<String,Object> field=new LinkedHashMap<>();field.put("name",f.getName());field.put("type",f.getType());
      field.put("access_flags",f.getAccessFlags());
      field.put("encoded_value_type",f.getInitialValue()==null?null:f.getInitialValue().getValueType());
      fields.add(field); // Do not publish constant values or credentials.
     }
     row.put("fields",fields);out.write(gson.toJson(row));out.newLine();count++;
    }
   }
  }
  System.out.println("Read classes: "+count+"; no app class loading");
 }
}
