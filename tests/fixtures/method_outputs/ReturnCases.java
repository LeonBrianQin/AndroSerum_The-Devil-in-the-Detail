package org.androserum.outputs;

public final class ReturnCases {
    public static String identity(String value) { return value; }
    public static String branch(boolean select, String left, String right) {
        if (select) return left;
        return right;
    }
    public static String mayThrow(boolean fail, String value) {
        if (fail) throw new IllegalStateException("selected exceptional exit");
        return value;
    }
    public static String neverReturns() { throw new IllegalStateException("no return"); }
    public static void voidReturn(String value) { value.length(); }
    public static String handled(boolean fail, String value) {
        try {
            if (fail) throw new IllegalStateException("caught");
            return value;
        } catch (IllegalStateException error) { return "fallback"; }
    }
    public static String caller(String value) { return identity(value); }
    public static String unrelated(String value) {
        String internallyUsed = value.toString();
        if (internallyUsed == null) return "null-path";
        return "fixed";
    }
}
