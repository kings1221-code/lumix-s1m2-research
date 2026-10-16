import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.android.tools.smali.baksmali.*;
import com.android.tools.smali.dexlib2.dexbacked.*;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.util.ClassFileNameHandler;
/** Uses the actual Baksmali library shipped in verified Apktool; selected classes only. */
public class SelectedSmali {
 public static void main(String[] a)throws Exception {
  Path out=Path.of(a[0]);Files.createDirectory(out);
  Set<String> wanted=Set.of("Ll0/h;","Lcom/google/android/gms/tasks/NativeOnCompleteListener;");
  BaksmaliOptions opt=new BaksmaliOptions();opt.debugInfo=false;opt.localsDirective=true;
  ClassFileNameHandler handler=new ClassFileNameHandler(out.toFile());int count=0;
  for(int n=1;n<a.length;n++) {
   DexBackedDexFile dex=new DexBackedDexFile(Files.readAllBytes(Path.of(a[n])),0);
   for(int i=0;i<dex.classCount;i++) {
    ClassDef c=(ClassDef)dex.classSection.get(i);
    if(wanted.contains(c.getType())) {
     if(!Baksmali.access$000(c,handler,opt))throw new IOException("Baksmali failed "+c.getType());
     count++;
    }
   }
  }
  if(count!=2)throw new AssertionError(count);
  System.out.println("Baksmali selected classes: "+count+"; no app execution");
 }
}
