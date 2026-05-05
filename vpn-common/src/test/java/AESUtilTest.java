import encryption.AESUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AESUtilTest {

    @Test
    void testGenerateAesKey() throws NoSuchAlgorithmException {
        SecretKey aesKeyGenerated = AESUtil.generateAesKey();
        Assertions.assertNotNull(aesKeyGenerated);
        Assertions.assertEquals("AES", aesKeyGenerated.getAlgorithm());
        Assertions.assertEquals(32, aesKeyGenerated.getEncoded().length);
    }

    @Test
    void testGenerateIV() {
        byte[] ivGenerated = AESUtil.generateIv();
        Assertions.assertNotNull(ivGenerated);
        Assertions.assertEquals(16, ivGenerated.length);
        byte[] secondIvGenerated = AESUtil.generateIv();
        Assertions.assertNotEquals(secondIvGenerated, ivGenerated);
    }

    @Test
    void testEncryptAndDecrypt() throws NoSuchPaddingException,
    NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
    IllegalBlockSizeException, BadPaddingException {
        SecretKey aesKeyGenerated = AESUtil.generateAesKey();
        byte[] ivGenerated = AESUtil.generateIv();
        byte[] plainText = "Hello World!".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedPlainText = AESUtil.encryptPlainText(plainText, aesKeyGenerated, ivGenerated);
        byte[] decryptedCipherText = AESUtil.decryptCipherText(encryptedPlainText, aesKeyGenerated, ivGenerated);
        Assertions.assertFalse(Arrays.equals(plainText, encryptedPlainText));
        Assertions.assertArrayEquals(plainText, decryptedCipherText);
    }

    @Test
    void testWongKeyFails() throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey aesKeyGeneratedFirst = AESUtil.generateAesKey();
        SecretKey aesKeyGeneratedSecond = AESUtil.generateAesKey();
        byte[] ivGeneratedOnly = AESUtil.generateIv();
        byte[] plainText = "OOOOOHHHH!".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedPlainText = AESUtil.encryptPlainText(plainText, aesKeyGeneratedFirst, ivGeneratedOnly);
        try {
            byte[] decryptedCipherText = AESUtil.decryptCipherText(encryptedPlainText, aesKeyGeneratedSecond,
                    ivGeneratedOnly);
            Assertions.assertFalse(Arrays.equals(plainText, decryptedCipherText));
        } catch (BadPaddingException e) {
            Assertions.assertTrue(true);
        }
    }


    @Test
    void testWrongIVFails() throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey aesKeyGenerated = AESUtil.generateAesKey();
        byte[] ivGeneratedFirst = AESUtil.generateIv();
        byte[] ivGeneratedSecond = AESUtil.generateIv();
        byte[] plainText = "remember when is the lowest form of conversation!".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedPlainText = AESUtil.encryptPlainText(plainText, aesKeyGenerated, ivGeneratedFirst);
        try {
            byte[] decryptedCipherText = AESUtil.decryptCipherText(encryptedPlainText, aesKeyGenerated,
                    ivGeneratedSecond);
            Assertions.assertFalse(Arrays.equals(plainText, decryptedCipherText));
        } catch (Exception e){
            Assertions.assertTrue(true);
        }
    }
}
