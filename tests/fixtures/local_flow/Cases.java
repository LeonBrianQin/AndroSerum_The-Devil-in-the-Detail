package org.androserum.local;
public final class Cases {
    public static volatile String received;
    public static volatile int receivedInt;
    public static class Box { public String value; }
    public static String readId() { return "fixture-id"; }
    public static String mayThrow() { return System.getProperty("androserum.fixture"); }
    public static String transform(String value) { return value; }
    public static void send(String value) { received=value; }
    public static void sendInt(int value) { receivedInt=value; }
    public static void copied(String x) { String a=x; String b=a; send(b); }
    public static void overwritten(String x) { String value=x; value="fixed"; send(value); }
    public static void readThenFixed() { String id=readId(); send("fixed"); if(id==null) received="none"; }
    public static void branch(String x,boolean flag) { String value; if(flag) value=x; else value="other"; send(value); }
    public static void loop(int x,int count) { int value=x; for(int i=0;i<count;i++) value=value+1; sendInt(value); }
    public static void exception(String previous) {
        String value=previous;
        try { value=mayThrow(); } catch(RuntimeException failure) { send(value); return; }
        send(value);
    }
    public static void differentFields(String x,Box left,Box right) { left.value=x; send(right.value); }
    public static void differentArrays(String x,String[] left,String[] right) { left[0]=x; send(right[0]); }
    public static void opaqueCall(String x) { send(transform(x)); }
}
