package org.androserum.crypto;
import java.security.MessageDigest;
import java.security.Key;
import javax.crypto.Cipher;
public class CryptoUse {
 public static byte[] digest(byte[] input) throws Exception { MessageDigest md=MessageDigest.getInstance("SHA-256");md.update(input);return md.digest(); }
 public static byte[] encrypt(Key key,byte[] input) throws Exception { Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key);return cipher.doFinal(input); }
}
