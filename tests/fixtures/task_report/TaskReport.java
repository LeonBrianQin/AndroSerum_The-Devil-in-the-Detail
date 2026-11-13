package org.androserum.taskreport;

import android.content.Context;
import android.telephony.TelephonyManager;
import android.util.Log;

/** Inert analysis fixture: no Android component is registered to execute it. */
public final class TaskReport {
  public static String inspectDevice(Context context) {
    TelephonyManager manager = (TelephonyManager) context.getSystemService("phone");
    String identifier = manager.getDeviceId();
    return identifier.toString();
  }

  public static void inspectSubscriber(Context context) {
    TelephonyManager manager = (TelephonyManager) context.getSystemService("phone");
    String subscriber = manager.getSubscriberId();
    Log.i("TaskReport", subscriber);
  }
}
