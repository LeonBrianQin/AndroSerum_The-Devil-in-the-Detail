package org.androserum.queryevidence;
import android.telephony.TelephonyManager;
public final class Cases {
 public static class Box { public String value; }
 public static volatile String received;
 public static void consume(String value){received=value;}
 public static void unrelated(String value){received=value;}
 public static void guarded(TelephonyManager manager,int count){
  String value=manager.getDeviceId();if(count>0)consume(value);unrelated(value);
 }
 public static void storage(TelephonyManager manager){
  Box a=new Box();Box b=new Box();String value=manager.getDeviceId();
  a.value=value;b.value="fixed";consume(a.value);unrelated(b.value);
 }
 public static String helper(TelephonyManager manager){return manager.getDeviceId();}
 public static void twice(TelephonyManager one,TelephonyManager two){consume(helper(one));unrelated(helper(two));}
}
