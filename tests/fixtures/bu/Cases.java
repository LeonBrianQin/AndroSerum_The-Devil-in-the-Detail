package org.androserum.bu;
import android.app.Activity;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import java.security.MessageDigest;

public class Cases extends Activity {
    public static volatile String observed;
    public static volatile byte[] observedBytes;
    public static class Box { String value; }
    public static void consume(String value) { observed=value; }
    public static void consumeBytes(byte[] value) { observedBytes=value; }
    public static void unrelatedBytes(byte[] value) { observedBytes=value; }
    public static void unrelated() { observed="unrelated-entry"; }
    public static void put(Box box,String value) { box.value=value; }
    public static String get(Box box) { return box.value; }
    public static String read(TelephonyManager manager) { return manager.getDeviceId(); }
    public static void sinkA(String value) { observed=value; }
    public static void sinkB(String value) { observed=value; }
    public static void twoCalls(TelephonyManager a,TelephonyManager b) {
        sinkA(read(a)); sinkB(read(b)); unrelated();
    }
    public static void twoObjects(TelephonyManager manager) {
        String id=manager.getDeviceId(); Box left=new Box(); Box right=new Box();
        put(left,id); put(right,"fixed-right"); sinkA(get(left)); sinkB(get(right)); unrelated();
    }
    public static byte[] shared(MessageDigest digest,byte[] input) {
        byte[] result=digest.digest(input); unrelatedBytes(input); consumeBytes(result); return result;
    }
    public static void loop(TelephonyManager manager,int count) {
        String value=read(manager);
        while(count-- > 0) { consume(value); }
        consume(value);
    }
    public static String copy(String value) { return value; }
    public static String recursive(TelephonyManager manager,int n) {
        String value=manager.getDeviceId();
        if(n>0) return recursive(manager,n-1);
        return value;
    }
    public static native String opaque(String value);
    public static void unknown(TelephonyManager manager) {
        String id=manager.getDeviceId(); String result=opaque(id); consume(result);
    }
    public static void guarded(TelephonyManager manager,boolean switchOn) {
        if(!switchOn)return; consume(read(manager));
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state); guarded((TelephonyManager)getSystemService(TELEPHONY_SERVICE),true); unrelated();
    }
}
