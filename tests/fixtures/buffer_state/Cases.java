package org.androserum.buffer;
import android.media.AudioRecord;
public class Cases {
    public static volatile short observed;
    private static void sink(short x) { observed=x; }
    private static short get(short[] a) { return a[0]; }
    public static void same(AudioRecord r) {
        short[] a=new short[4]; int n=r.read(a,0,4);
        if(n>0) sink(a[0]);
    }
    public static void different(AudioRecord r) {
        short[] a=new short[4], b=new short[4]; int n=r.read(a,0,4);
        if(n>0) sink(b[0]);
    }
    public static void failed(AudioRecord r) {
        short[] a=new short[4]; int n=r.read(a,0,4);
        if(n<0) sink(a[0]);
    }
    public static void zero(AudioRecord r) {
        short[] a=new short[4]; int n=r.read(a,0,4);
        if(n==0) sink(a[0]);
    }
    public static void disjoint(AudioRecord r) {
        short[] a=new short[4]; int n=r.read(a,1,3);
        if(n>0) sink(a[0]);
    }
    public static void helper(AudioRecord r) {
        short[] a=new short[4]; int n=r.read(a,0,4);
        if(n>0) sink(get(a));
    }
    public static void exceptional(AudioRecord r) {
        short[] a=new short[4];
        try { r.read(a,0,4); } catch(RuntimeException e) { sink(a[0]); }
    }
    public static void overwritten(AudioRecord r) {
        short[] a=new short[4]; int n=r.read(a,0,4); a[0]=7;
        if(n>0) sink(a[0]);
    }
    public static void unknownResult(AudioRecord r) {
        short[] a=new short[4]; r.read(a,0,4); sink(a[0]);
    }
    public static void shortRead(AudioRecord r) {
        short[] a=new short[4]; int n=r.read(a,0,4);
        if(n==1) sink(a[2]);
    }
    public static void priorContents(AudioRecord r) {
        short[] a=new short[4]; a[0]=7; int n=r.read(a,0,4);
        if(n<=0) sink(a[0]);
    }
    public static void dynamicIndex(AudioRecord r,int i) {
        short[] a=new short[4]; int n=r.read(a,0,4);
        if(n>0) sink(a[i]);
    }
    public static void unknownBuffer(AudioRecord r,short[] a) {
        int n=r.read(a,0,4); if(n>0) sink(a[0]);
    }
    public static void zeroRequest(AudioRecord r) {
        short[] a=new short[4]; r.read(a,0,0); sink(a[0]);
    }
    public static void invalidRange(AudioRecord r) {
        short[] a=new short[4]; int n=r.read(a,3,4);
        if(n>0) sink(a[3]);
    }
    public static void opaqueCall(AudioRecord r) {
        short[] a=new short[4]; int n=r.read(a,0,4);
        System.gc();
        if(n>0) sink(a[0]);
    }
}
