import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.Gson;

/** Own reconstruction from selected DEX only; does not load APK classes or open sockets.
 * Host JDK behavior is a synthetic control, not Android/device execution evidence.
 */
public class SyntheticTransportTest {
    static int n(long length, int b) { return (int)Math.ceil(length/(double)b); }
    static int offset(int index, int b) { return index*b; }
    static int length(long length, int index, int b) {
        return (int)Math.min(length, ((long)(index+1))*b)-offset(index,b);
    }
    static Map<String,Object> read(Path file, long observedLength, int index, int b) throws Exception {
        int start=offset(index,b), planned=length(observedLength,index,b);
        byte[] bytes=new byte[planned];
        long skipped; int got;
        try(FileInputStream in=new FileInputStream(file.toFile())) {
            skipped=in.skip(start); got=in.read(bytes);
        }
        // We record return values for the test. Original x0 ignores them.
        Map<String,Object> r=new LinkedHashMap<>();
        r.put("index",index);r.put("offset",start);r.put("planned_length",planned);
        r.put("actual_skip",skipped);r.put("actual_read",got);
        r.put("request_body_length",bytes.length);
        r.put("body_hex",HexFormat.of().formatHex(bytes));
        return r;
    }
    static String select(Path root,List<Path> list) {
        for(Path p:list) {
            if(p!=null && Files.isRegularFile(p)) {
                String base=p.getFileName().toString();
                if(!root.toString().isEmpty()&&!base.isEmpty())return root.resolve(base).toString();
            }
        }
        return null;
    }
    static Map<String,Object> selection(Path root, List<Path> list, String label) {
        String selected=select(root,list);
        return Map.of("case",label,"selected",root.relativize(Path.of(selected)).toString().replace('\\','/'),
                      "selected_exists",Files.isRegularFile(Path.of(selected)));
    }
    static Map<String,Object> success(int index, int count, boolean sending, int operationState) {
        int next=index+1;
        String action=next<count&&sending?"next_chunk":next==count?"DETAIL_TRANSFERRED":"no_transition";
        return Map.of("before_index",index,"count",count,"sending",sending,
                      "operation_state_before",operationState,"after_index",next,"action",action,
                      "operation_state_after",next==count?0:operationState);
    }
    public static void main(String[] args) throws Exception {
        Path work=Path.of(args[0]).toAbsolutePath();
        Files.createDirectory(work); // Refuses existing evidence directory.
        byte[] source=new byte[21];for(int i=0;i<source.length;i++)source[i]=(byte)(i+1);
        Path normal=work.resolve("synthetic.bin");Files.write(normal,source,StandardOpenOption.CREATE_NEW);
        List<Object> normalReads=new ArrayList<>();ByteArrayOutputStream combined=new ByteArrayOutputStream();
        for(int i=0;i<n(source.length,8);i++) {
            Map<String,Object> r=read(normal,source.length,i,8);normalReads.add(r);
            combined.write(HexFormat.of().parseHex((String)r.get("body_hex")));
        }
        if(!Arrays.equals(source,combined.toByteArray()))throw new AssertionError("normal bytes changed");
        Path shortFile=work.resolve("truncated.bin");Files.write(shortFile,Arrays.copyOf(source,17),StandardOpenOption.CREATE_NEW);
        Map<String,Object> shortRead=read(shortFile,21,2,8);
        if(!shortRead.get("actual_read").equals(1)||!shortRead.get("request_body_length").equals(5)
           ||!shortRead.get("body_hex").equals("1100000000"))throw new AssertionError(shortRead.toString());
        Path root=work.resolve("extraction");Files.createDirectory(root);
        Path binary=root.resolve("firmware.bin");Files.write(binary,new byte[]{1},StandardOpenOption.CREATE_NEW);
        Path note=root.resolve("readme.txt");Files.writeString(note,"synthetic note",StandardOpenOption.CREATE_NEW);
        Path nestedDir=root.resolve("subdir");Files.createDirectory(nestedDir);
        Path nested=nestedDir.resolve("nested.bin");Files.write(nested,new byte[]{2},StandardOpenOption.CREATE_NEW);
        List<Object> selectors=List.of(selection(root,List.of(binary),"flat_bin"),
                selection(root,List.of(note,binary),"readme_before_bin"),
                selection(root,List.of(nested),"nested_bin_parent_discarded"),
                selection(root,List.of(nestedDir,binary),"directory_skipped"));
        if(!select(root,List.of(note,binary)).equals(note.toString()))throw new AssertionError();
        if(Files.exists(Path.of(select(root,List.of(nested)))))throw new AssertionError();
        Map<String,Object> result=new LinkedHashMap<>();
        result.put("scope","Own Java reconstruction + synthetic host files; not the APK or an Android runtime");
        result.put("normal_21_bytes_chunk_size_8",normalReads);
        result.put("normal_reassembled_equal",true);
        result.put("captured_length_21_actual_length_17_last_chunk",shortRead);
        result.put("selection_cases",selectors);
        result.put("success_transition_cases",List.of(success(0,3,true,1),success(2,3,true,1),success(2,3,true,4)));
        result.put("zero_length_model",Map.of("length",0,"chunk_count",n(0,8),"first_planned_length",length(0,0,8)));
        result.put("limitations",List.of("Short read is induced by a smaller synthetic file after an assumed earlier length observation.",
          "Does not demonstrate spontaneous short reads on an unchanged regular file or camera acceptance.",
          "Selector tests reconstruct only the selection step; do not run vendor extraction or app code.",
          "Final-ack/cancel model follows selected DEX branches, not a measured concurrency schedule."));
        String json=new Gson().toJson(result);
        Files.writeString(work.resolve("result.json"),json+"\n",StandardOpenOption.CREATE_NEW);
        System.out.println("PASS: normal chunks, induced short read, 4 selection cases, 3 success transitions and zero-length formulas");
    }
}
