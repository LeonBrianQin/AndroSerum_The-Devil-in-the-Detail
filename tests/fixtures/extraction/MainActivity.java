package org.androserum.extraction;

import android.app.Activity;
import android.os.Bundle;

public final class MainActivity extends Activity {
    public static String last;
    public static final float NAN = Float.NaN;
    public static final long LARGE = 0x1122334455667788L;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        consume("alpha");
        consume("beta");
        instanceSink("receiver");
        wide(0x1122334455667788L, Double.POSITIVE_INFINITY, "wide");
        String message = readMessage();
        consume(Helper.decorate(message));
        int[] values = new int[] {3, 5};
        if (state != null) { last = Integer.toString(values[1]); }
    }

    public static void consume(String value) { last = value; }
    public String readMessage() { return getString(R.string.message); }
    public void instanceSink(String value) { last = value; }
    public static void wide(long number, double decimal, String value) { last = value; }
    public static String arrayUpdate(int[] values) { values[0] = values[1]; return last; }
    public static int resourceLookingInteger() { return R.string.message; }
}
