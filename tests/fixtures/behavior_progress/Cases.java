package org.androserum.behaviorprogress;
import android.app.Activity;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;

public final class Cases extends Activity {
    public void collect(TelephonyManager manager) {
        String device = manager.getDeviceId();
        String subscriber = manager.getSubscriberId();
        record(device, subscriber);
        unrelated();
    }
    private void record(String device, String subscriber) {
        logLine(device);
        logLine(subscriber);
    }
    private void logLine(String text) {
        String tag = getString(R.string.audit_tag);
        Log.i(tag, text);
    }
    public void fixed(TelephonyManager manager) {
        String unused = manager.getDeviceId();
        record("fixed diagnostic message", "fixed subscriber message");
    }
    public static void unrelated() { Log.i("Separate", "independent heartbeat"); }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TelephonyManager manager=(TelephonyManager)getSystemService(TELEPHONY_SERVICE);
        collect(manager);
        fixed(manager);
    }
}
