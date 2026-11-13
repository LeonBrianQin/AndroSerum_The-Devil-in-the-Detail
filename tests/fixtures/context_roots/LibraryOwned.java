package javax.androserum;

// Defined by the APK, despite its library-looking namespace.
public class LibraryOwned {
    public static String passthrough(String input) { return input; }
    public static native String unsupportedNative(String input);
}
