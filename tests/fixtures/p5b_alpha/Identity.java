package org.androserum.p5balpha;
import android.content.Context;
import android.telephony.TelephonyManager;
public final class Identity {
  public static String inspect(Context context) {
    Object service = context.getSystemService("phone");
    TelephonyManager manager = (TelephonyManager) service;
    String identifier = manager.getDeviceId();
    return identifier.toString();
  }
}
