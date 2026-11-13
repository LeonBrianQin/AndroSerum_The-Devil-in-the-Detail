package org.androserum.fixture;

import android.app.Activity;
import android.os.Bundle;

/** Benign, deterministic fixture for checking the analysis toolchain. */
public final class MainActivity extends Activity {
    private static volatile String observed;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        sink(source());
    }

    public static String source() {
        return "fixture-value";
    }

    public static void sink(String value) {
        observed = value;
    }
}
