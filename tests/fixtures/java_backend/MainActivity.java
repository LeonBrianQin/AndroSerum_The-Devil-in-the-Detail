package org.androserum.jimple;
import android.app.Activity;
import android.os.Bundle;
public final class MainActivity extends Activity {
    public static String last;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        sink("left"); sink("right");
        if(state!=null) sink(guarded("abc"));
    }
    public static void sink(String value) { last=value; }
    public static int overloaded(int value) { return value+1; }
    public static String overloaded(String[] values) { return values[0]; }
    public static int[][] arrays(int[][][] values) { return values[0]; }
    public static String guarded(String value) {
        try { return value.substring(1); } catch(RuntimeException failure) { return "fallback"; }
    }
    public static int select(int value) {
        switch(value) { case 1:return 10; case 2:return 20; case 3:return 30; default:return 0; }
    }
    public native void nativeThing();
}
