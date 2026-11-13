package org.androserum.buadapter;
import android.app.Activity;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import java.security.MessageDigest;

public class Cases extends Activity {
    public static volatile String observed;
    public static class Echo { public String copy(String x) { return x; } }
    public static void consume(String x) { observed=x; }
    public static void flowSink(String x) { observed=x; }
    public static void originalSink(String x) { observed=x; }
    public static void unrelatedSink(String x) { observed=x; }
    public static void unrelated() { observed="unrelated"; }
    public static String read(TelephonyManager m) { return m.getDeviceId(); }
    public static void ifPositive(TelephonyManager m,int n) {
        if(n>0)consume(read(m));
    }
    public static void compare(TelephonyManager m,int a,int b) {
        if(a>b)consume(read(m));
    }
    public static void compareTwice(TelephonyManager m,int a,int b,int c,int d) {
        compare(m,a,b); compare(m,c,d);
    }
    public static void crossMethod(TelephonyManager m) { flowSink(read(m)); }
    public static void virtualFlow(TelephonyManager m) {
        String id=m.getDeviceId();
        Echo echo=new Echo(); String output=echo.copy(id);
        flowSink(output); originalSink(id); unrelated();
    }
    public static void negative(TelephonyManager m) {
        String unused=m.getDeviceId(); flowSink("fixed");
    }
    public static void twice(TelephonyManager a,TelephonyManager b) {
        virtualFlow(a); virtualFlow(b);
    }
    public static void sharedSource(TelephonyManager m) throws Exception {
        String id=m.getDeviceId(); MessageDigest.getInstance(id); unrelatedSink(id);
    }
    public static void reverseSummary(TelephonyManager m) throws Exception {
        String id=m.getDeviceId(); Echo echo=new Echo(); String output=echo.copy(id);
        MessageDigest.getInstance(output); originalSink(id);
    }
    public static void recursiveFlow(TelephonyManager m,int n) {
        String id=m.getDeviceId(); Echo echo=new Echo(); flowSink(echo.copy(id));
        if(n>0)recursiveFlow(m,n-1); originalSink(id);
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TelephonyManager m=(TelephonyManager)getSystemService(TELEPHONY_SERVICE);
        ifPositive(m,1); compare(m,2,1); compareTwice(m,3,2,1,4); crossMethod(m);
        virtualFlow(m); negative(m); twice(m,m); recursiveFlow(m,1);
        try { sharedSource(m); reverseSummary(m); } catch(Exception ignored) { unrelated(); }
    }
}
