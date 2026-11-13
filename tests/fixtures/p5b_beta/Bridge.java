package org.androserum.p5bbeta;
import android.content.Context;
import android.telephony.TelephonyManager;
public final class Bridge {
  private static TelephonyManager lookup(Context context) {
    Object service = context.getSystemService("phone");
    return (TelephonyManager) service;
  }
  private static String stringify(String input) { return input.toString(); }
  public static String inspect(Context context) {
    TelephonyManager manager = lookup(context);
    String value = manager.getDeviceId();
    return stringify(value);
  }
}
