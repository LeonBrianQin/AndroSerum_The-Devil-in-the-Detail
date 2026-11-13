package org.androserum.bujca;
import java.security.MessageDigest;

/** Inert static-analysis input. The APK is never installed or executed. */
public final class Cases {
 public static native void consumeA(byte[] value);
 public static native void consumeB(byte[] value);
 public static void adjacentIndependent(byte[] first, byte[] second) throws Exception {
  MessageDigest a=MessageDigest.getInstance("MD5");a.update(first);byte[] x=a.digest();
  MessageDigest b=MessageDigest.getInstance("MD5");b.update(second);byte[] y=b.digest();
  consumeA(x);consumeB(y);
 }
 public static void sharedInput(byte[] input) throws Exception {
  MessageDigest a=MessageDigest.getInstance("MD5");a.update(input);byte[] x=a.digest();
  MessageDigest b=MessageDigest.getInstance("MD5");b.update(input);byte[] y=b.digest();
  consumeA(x);consumeB(y);
 }
 public static void sameStateLater(byte[] input) throws Exception {
  MessageDigest a=MessageDigest.getInstance("MD5");a.update(input);byte[] x=a.digest();
  byte[] y=a.digest();consumeA(x);consumeB(y);
 }
}
