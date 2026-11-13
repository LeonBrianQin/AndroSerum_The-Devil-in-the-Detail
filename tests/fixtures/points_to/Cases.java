package org.androserum.points;
public final class Cases {
 public interface Op { String map(String value); }
 public static class A implements Op { public String map(String value){
  try{java.security.MessageDigest.getInstance("MD5");}catch(java.security.NoSuchAlgorithmException unavailable){}
  return value;
 } }
 public static class B implements Op { public String map(String value){return "B-fixed";} }
 public static class C implements Op { public String map(String value){return "C-never-receiver";} }
 public static class Child extends A {}
 public static class Box { public Op member; }
 public static volatile String received;
 public static void send(String value){received=value;}
 public static Op identity(Op value){return value;}
 public static String helper(Op value,String input){return value.map(input);}
 public static void distinct(String first,String second){Op a=new A();Op b=new B();send(a.map(first));send(b.map(second));}
 public static void merged(boolean flag,String input){Op value=flag?new A():new B();send(value.map(input));}
 public static void across(String input){Op a=identity(new A());send(helper(a,input));}
 public static void twoHelpers(String one,String two){send(helper(new A(),one));send(helper(new B(),two));}
 public static void fields(String input){Box box=new Box();box.member=new A();send(box.member.map(input));}
 public static void arrays(String input){Op[] ops={new A(),new B()};send(ops[0].map(input));}
 public static void inherited(String input){Op value=new Child();send(value.map(input));}
 public static void unused(){Op value=new C();}
 public static void emptyLiteral(){send("");send("\n");}
 public static void nullReceiver(String input){Op value=null;send(value.map(input));}
}
