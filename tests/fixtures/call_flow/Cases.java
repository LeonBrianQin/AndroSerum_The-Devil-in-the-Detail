package org.androserum.calls;

public class Cases {
    public static volatile String received;
    public static void send(String value) { received=value; }
    public static String identity(String x) { return x; }
    public static String ignore(String x) { return "fixed"; }
    public static String wide(long ignored,String x,double other) { return x; }
    public String instance(String x) { return x; }
    public Cases self() { return this; }
    public static volatile Cases receivedObject;
    public static void sendObject(Cases value) { receivedObject=value; }
    public static void receiverReturn(Cases value) { sendObject(value.self()); }
    private String privateIdentity(String x) { return x; }
    public String callPrivate(String x) { return privateIdentity(x); }
    public static void callerA() { send(identity("id-A")); }
    public static void callerB() { send(identity("fixed-B")); }
    public static void sameCaller(String id) { String a=identity(id); String b=identity("fixed"); send(b); send(a); }
    public static void ignored(String id) { send(ignore(id)); }
    public static String levelTwo(String id) { return identity(id); }
    public static String levelOne(String id) { return levelTwo(id); }
    public static void nested(String id) { send(levelOne(id)); }
    public static void wideCaller(String id) { send(wide(0x1122334455667788L,id,2.5)); }
    public static String normalAndThrow(String id,boolean fail) {
        if(fail) throw new IllegalStateException("fixture");
        return id;
    }
    public static void exceptional(String previous,String id,boolean flag) {
        String value=previous;
        try { value=normalAndThrow(id,flag); } catch(RuntimeException failure) { send(value); return; }
        send(value);
    }
    public static String onlyThrow(String id) { throw new IllegalStateException(id); }
    public static void throwCaller(String id) { send(onlyThrow(id)); }
    public static String recursive(String id,int count) { if(count<=0) return id; return recursive(id,count-1); }
    public static void recursiveCaller(String id,int count) { send(recursive(id,count)); }
    public interface Mapper { String map(String x); }
    public static class First implements Mapper { public String map(String x) { return x; } }
    public static class Second implements Mapper { public String map(String x) { return "second"; } }
    public static void interfaceCaller(Mapper mapper,String id) { send(mapper.map(id)); }
    public static class Base { public String pass(String x) { return x; } }
    public static class Child extends Base {
        public String pass(String x) { return "child"; }
        public String superPass(String x) { return super.pass(x); }
    }
    public static void virtualCaller(Base base,String id) { send(base.pass(id)); }
    public static void receiverCaller(Cases instance,String id) { send(instance.instance(id)); }
    public static String library(String key) { return System.getProperty(key); }
    public static void libraryCaller(String id) { send(library(id)); }
    public static String overloaded(String id) { return id; }
    public static String overloaded(int id) { return "integer"; }
    public static void overloadCaller(String id) { send(overloaded(id)); send(overloaded(1)); }
}
