package utilities;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class EncryptConstants {

    // AES methods
    public static SecretKey generateAesKey() throws NoSuchAlgorithmException {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey aesKey = aesKeyGen.generateKey();
        return aesKey;
    }

    public static byte[] generateIv() {
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static byte[] encryptPlainText(byte[] plainText, SecretKey aesKey, byte[] iv) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        String transformation = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);
        return cipher.doFinal(plainText);
    }

    public static byte[] decryptCipherText(byte[] cipherText, SecretKey aesKey, byte[] iv) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String transformation = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
        return cipher.doFinal(cipherText);
    }

}
