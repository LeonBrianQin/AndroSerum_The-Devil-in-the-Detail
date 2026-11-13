package org.androserum.flowsummary;

/** Static-analysis input only. Neither the APK nor native methods execute. */
public final class Cases {
 public static native String source();
 public static native void positiveSink(String value);
 public static native void receiverSink(String value);
 public static native void fixedSink(String value);
 public static native void separateSink(String value);
 public static native void sanitizedSink(String value);
 public static String before(String input) {return input;}
 public static String after(String input) {return input;}
 public static String sanitize(String ignored) {return "fixed";}
 public static String build(String input) {
  StringBuilder buffer=new StringBuilder();buffer.append(input);return buffer.toString();
 }
 public static void positiveCrossMethod() {
  String input=source();positiveSink(after(build(before(input))));
 }
 public static void positiveReceiverState() {
  StringBuffer buffer=new StringBuffer();buffer.append(source());receiverSink(buffer.toString());
 }
 public static void negativeFixed() {
  String input=source();build(before(input));fixedSink("fixed");
 }
 public static void negativeDifferentObject() {
  StringBuilder first=new StringBuilder();StringBuilder second=new StringBuilder();
  first.append(source());second.append("fixed");separateSink(second.toString());
 }
 public static void negativeHelperReturnsConstant() {
  String input=source();sanitizedSink(build(sanitize(input)));
 }
}
