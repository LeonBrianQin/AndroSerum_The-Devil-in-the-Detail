package org.androserum.heap;

public class Cases {
    public static volatile String received;
    public static volatile String first;
    public static volatile String second;
    public static class Box { public String value; public String other; }
    public static class Parent { public String value; }
    public static class Child extends Parent { public String value; }
    public static void send(String value) { received=value; }
    public static native void unknown(Object value);
    public static void sameObject(String x) { Box box=new Box(); box.value=x; send(box.value); }
    public static void alias(String x) { Box box=new Box(); Box alias=box; alias.value=x; send(box.value); }
    public static void differentObjects(String x) { Box left=new Box(); Box right=new Box(); left.value=x; send(right.value); }
    public static void differentFields(String x) { Box box=new Box(); box.value=x; send(box.other); }
    public static void hiddenFields(String x) { Child child=new Child(); Parent parent=child; parent.value=x; child.value="child"; send(parent.value); send(child.value); }
    public static void overwritten(String x) { Box box=new Box(); box.value=x; box.value="fixed"; send(box.value); }
    public static void readBeforeWrite(String x) { Box box=new Box(); String before=box.value; box.value=x; send(before); }
    public static void sameArray(String x) { String[] array=new String[2]; array[0]=x; send(array[0]); }
    public static void arrayAlias(String x) { String[] array=new String[2]; String[] alias=array; alias[0]=x; send(array[0]); }
    public static void differentIndices(String x) { String[] array=new String[2]; array[0]=x; send(array[1]); }
    public static void differentArrays(String x) { String[] left=new String[2]; String[] right=new String[2]; left[0]=x; send(right[0]); }
    public static void arrayOverwrite(String x) { String[] array=new String[2]; array[0]=x; array[0]="fixed"; send(array[0]); }
    public static void unknownIndex(String x,int index) { String[] array=new String[2]; array[0]="old"; array[index]=x; send(array[0]); }
    public static void unknownReadIndex(String x,int index) { String[] array=new String[2]; array[0]=x; array[1]="other"; send(array[index]); }
    public static void parameterBases(String x,Box a,Box b) { a.value=x; send(b.value); }
    public static void unknownBaseWrite(String x,Box unknown) { Box box=new Box(); box.value="old"; unknown.value=x; send(box.value); }
    public static void callEffect(String x) { Box box=new Box(); box.value=x; unknown(box); send(box.value); }
    public static void exceptionalCall(String x) { Box box=new Box(); box.value=x; try { unknown(box); } catch(RuntimeException e) { send(box.value); } }
    public static void exceptionalArray(String x,String y,int index) {
        String[] array=new String[1]; array[0]=x;
        try { array[index]=y; } catch(RuntimeException e) { send(array[0]); return; }
        send(array[0]);
    }
    public static void branch(String x,boolean flag) { Box box=new Box(); if(flag) box.value=x; else box.value="other"; send(box.value); }
    public static void loop(String x,int count) { Box box=new Box(); box.value=x; for(int i=0;i<count;i++) box.value="loop"; send(box.value); }
    public static void repeatedAllocation(String x,int count) { for(int i=0;i<count;i++) { Box box=new Box(); box.value=x; send(box.value); } }
    public static void multipleObjects(String x,boolean flag) {
        Box left=new Box(); Box right=new Box(); left.value="left"; right.value="right";
        Box chosen=flag?left:right; chosen.value=x; send(left.value);
    }
    public static void staticSame(String x) { first=x; send(first); }
    public static void staticDifferent(String x) { first=x; send(second); }
    public static void staticOverwrite(String x) { first=x; first="fixed"; send(first); }
}
