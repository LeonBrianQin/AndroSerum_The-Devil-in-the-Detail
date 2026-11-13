package org.androserum.context;
import android.telephony.TelephonyManager;
import android.util.Log;

public class Cases {
    public static class Box {
        public String value; public String other;
        private void putPrivate(String x) { value=x; }
        private String getPrivate() { return value; }
    }
    public static volatile String received;
    public static void send(String x) { received=x; }
    public static native void unknown(Box box);
    public static void put(Box box,String value) { box.value=value; }
    public static String get(Box box) { return box.value; }
    public static void putOther(Box box,String value) { box.other=value; }
    public static void putNested(Box box,String value) { put(box,value); }
    public static String getNested(Box box) { return get(box); }
    public static Box create() { return new Box(); }
    public static void twoObjects(String leftId,String rightId) {
        Box left=new Box();Box right=new Box();put(left,leftId);put(right,rightId);send(get(left));send(get(right));
    }
    public static void fixedRight(String id) {
        Box left=new Box();Box right=new Box();put(left,id);put(right,"fixed");send(get(right));
    }
    public static void callerA() { Box box=new Box();put(box,"A");send(get(box)); }
    public static void callerB() { Box box=new Box();put(box,"B");send(get(box)); }
    public static void overwritten(String id) { Box box=new Box();put(box,id);put(box,"fixed");send(get(box)); }
    public static void alias(String id) { Box box=new Box();Box other=box;put(other,id);send(get(box)); }
    public static void privateHelpers(String id) { Box box=new Box();box.putPrivate(id);send(box.getPrivate()); }
    public static void nested(String id) { Box box=new Box();putNested(box,id);send(getNested(box)); }
    public static void factories(String a,String b) { Box left=create();Box right=create();put(left,a);put(right,b);send(get(left));send(get(right)); }
    public static void wrongField(String id) { Box box=new Box();putOther(box,id);send(get(box)); }
    public static void unknownEffect(String id) { Box box=new Box();put(box,id);unknown(box);send(get(box)); }
    public static void putThenMaybeThrow(Box box,String value,boolean fail) { put(box,value);if(fail)throw new IllegalStateException(); }
    public static void exceptional(String previous,String next,boolean flag) {
        Box box=new Box();put(box,previous);
        try { putThenMaybeThrow(box,next,flag); } catch(RuntimeException failure) { send(get(box));return; }
        send(get(box));
    }
    public static void putArray(String[] array,int index,String value) { array[index]=value; }
    public static String getArray(String[] array,int index) { return array[index]; }
    public static void arrays(String a,String b) { String[] array=new String[2];putArray(array,0,a);putArray(array,1,b);send(getArray(array,0));send(getArray(array,1)); }
    public static String recursive(Box box,int count) { if(count<=0)return get(box);return recursive(box,count-1); }
    public static void recursion(String id,int count) { Box box=new Box();put(box,id);send(recursive(box,count)); }
    public static void sourceUse(TelephonyManager manager) {
        Box box=new Box();put(box,manager.getDeviceId());send(get(box));Log.d("fixture",get(box));
    }
    public static void twoSources(TelephonyManager manager) { String a=manager.getDeviceId();String b=manager.getDeviceId();send(a);send(b); }
    public interface Reader { String read(); }
    public static class ReaderImpl implements Reader { public String read() { return "reader"; } }
    public static void candidateUse(Reader reader) { send(reader.read()); }
}
