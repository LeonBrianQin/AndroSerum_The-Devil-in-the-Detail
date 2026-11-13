package org.androserum.audiosites;
import android.media.AudioRecord;
public class Cases {
    public static volatile int samples=8, observed, status;
    private static int pair(short[] a) {
        Double sum=Double.valueOf(0.0);
        for(int i=0;i<a.length;i++) {
            sum=Double.valueOf(sum.doubleValue()+a[i]*a[i]);
        }
        return sum.intValue();
    }
    private static int startsOne(short[] a) {
        Double sum=Double.valueOf(0.0);
        for(int i=1;i<a.length;i++) sum=Double.valueOf(sum.doubleValue()+a[i]*a[i]);
        return sum.intValue();
    }
    private static int nonStrict(short[] a) {
        Double sum=Double.valueOf(0.0);
        for(int i=0;i<=a.length;i++) sum=Double.valueOf(sum.doubleValue()+a[i]*a[i]);
        return sum.intValue();
    }
    private static int stepTwo(short[] a) {
        Double sum=Double.valueOf(0.0);
        for(int i=0;i<a.length;i+=2) sum=Double.valueOf(sum.doubleValue()+a[i]*a[i]);
        return sum.intValue();
    }
    public static void positive(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);status=n;observed=pair(a);
    }
    public static void shortResult(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);if(n==1) observed=pair(a);
    }
    public static void failed(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);if(n<0) observed=pair(a);
    }
    public static void zero(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);if(n==0) observed=pair(a);
    }
    public static void different(AudioRecord r) {
        short[] a=new short[samples],b=new short[samples];int n=r.read(a,0,samples-1);status=n;observed=pair(b);
    }
    public static void overwrite(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);status=n;a[0]=7;observed=pair(a);
    }
    public static void opaque(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);status=n;System.gc();observed=pair(a);
    }
    public static void badInit(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);status=n;observed=startsOne(a);
    }
    public static void badGuard(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);status=n;observed=nonStrict(a);
    }
    public static void badStep(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);status=n;observed=stepTwo(a);
    }
    public static void repeatedHelper(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples-1);status=n;observed=pair(a)+pair(a);
    }
    public static void unsupportedCount(AudioRecord r) {
        short[] a=new short[samples];int n=r.read(a,0,samples*2);status=n;observed=pair(a);
    }
}
