package org.androserum.jca;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Compiled static-analysis inputs only. The APK is never installed/executed. */
public final class Cases {
 public static native void unknownMutation();
 public static byte[] unknownEffect(byte[] input) throws Exception {
  MessageDigest d=MessageDigest.getInstance("MD5");d.update(input);unknownMutation();return d.digest();
 }
 public static byte[] digest(byte[] input) throws Exception {
  MessageDigest d=MessageDigest.getInstance("MD5");d.update(input);return d.digest();
 }
 public static byte[] different(byte[] input) throws Exception {
  MessageDigest a=MessageDigest.getInstance("MD5"),b=MessageDigest.getInstance("MD5");a.update(input);return b.digest();
 }
 public static byte[] wrongFactoryFamily(byte[] input) throws Exception {
  MessageDigest d=(MessageDigest)(Object)Cipher.getInstance("AES");d.update(input);return d.digest();
 }
 public static byte[] reversed(byte[] input) throws Exception {
  MessageDigest d=MessageDigest.getInstance("MD5");byte[] out=d.digest();d.update(input);return out;
 }
 public static byte[] reset(byte[] input) throws Exception {
  MessageDigest d=MessageDigest.getInstance("MD5");d.update(input);d.reset();return d.digest();
 }
 public static byte[] nullUpdate() throws Exception {
  MessageDigest d=MessageDigest.getInstance("MD5");d.update((byte[])null);return d.digest();
 }
 public static byte[] failed(byte[] input) throws Exception {
  MessageDigest d=MessageDigest.getInstance("MD5");try{d.update(input);}catch(RuntimeException e){return d.digest();}return new byte[0];
 }
 public static byte[] repeated(byte[][] inputs) throws Exception {
  MessageDigest d=null;for(byte[] input:inputs){d=MessageDigest.getInstance("MD5");d.update(input);}return d.digest();
 }
 public static byte[] encrypt(byte[] key,byte[] input) throws Exception {
  SecretKeySpec k=new SecretKeySpec(key,"AES");Cipher c=Cipher.getInstance("AES");c.init(1,k);return c.doFinal(input);
 }
 public static byte[] decrypt(byte[] key,byte[] input) throws Exception {
  SecretKeySpec k=new SecretKeySpec(key,"AES");Cipher c=Cipher.getInstance("AES");c.init(2,k);return c.doFinal(input);
 }
 public static byte[] invalidMode(byte[] key,byte[] input) throws Exception {
  SecretKeySpec k=new SecretKeySpec(key,"AES");Cipher c=Cipher.getInstance("AES");c.init(0,k);return c.doFinal(input);
 }
 public static byte[] nullKey(byte[] input) throws Exception {
  Cipher c=Cipher.getInstance("AES");c.init(1,(java.security.Key)null);return c.doFinal(input);
 }
 public static byte[] differentCipher(byte[] key,byte[] input) throws Exception {
  SecretKeySpec k=new SecretKeySpec(key,"AES");Cipher a=Cipher.getInstance("AES"),b=Cipher.getInstance("AES");a.init(1,k);return b.doFinal(input);
 }
 public static byte[] overwrite(byte[] key,byte[] input) throws Exception {
  SecretKeySpec k=new SecretKeySpec(key,"AES");Cipher c=Cipher.getInstance("AES");c.init(1,k);c.init(2,k);return c.doFinal(input);
 }
 public static byte[] failedInit(byte[] key,byte[] input) throws Exception {
  SecretKeySpec k=new SecretKeySpec(key,"AES");Cipher c=Cipher.getInstance("AES");try{c.init(1,k);}catch(Exception e){return c.doFinal(input);}return new byte[0];
 }
}
