import encryption.AESUtil;
import encryption.EncryptedMessage;
import encryption.HMACUtil;
import encryption.SessionCrypto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SessionCryptoTest {

    @Test
    public void nullAesKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
        SecretKey secretKey = keyGenerator.generateKey();
        Throwable assertion = assertThrows(IllegalArgumentException.class, () -> {
            new SessionCrypto(null, secretKey.getEncoded());
        });
        assertEquals("AES key and HMAC key cannot be null", assertion.getMessage());
    }

    @Test
    public void nullHmacKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();
        Throwable assertion = assertThrows(IllegalArgumentException.class, () -> {
            new SessionCrypto(secretKey, null);
        });
        assertEquals("AES key and HMAC key cannot be null", assertion.getMessage());
    }

    @Test
    public void nullPlainText() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey aesKey = keyGenerator.generateKey();
        KeyGenerator keyGenerator2 = KeyGenerator.getInstance("HmacSHA256");
        SecretKey hmacKey = keyGenerator2.generateKey();
        SessionCrypto sessionCrypto = new SessionCrypto(aesKey, hmacKey.getEncoded());
        Throwable assertion = assertThrows(IllegalArgumentException.class, () -> {
            sessionCrypto.encrypt(null);
        });
        assertEquals("Plaintext cannot be null", assertion.getMessage());
    }

    @Test
    public void encryptResultsValidMessage() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();
        KeyGenerator keyGenerator2 = KeyGenerator.getInstance("HmacSHA256");
        SecretKey hmacKey = keyGenerator2.generateKey();
        SessionCrypto sessionCrypto = new SessionCrypto(secretKey, hmacKey.getEncoded());
        byte[] currentPlainText = "hello world".getBytes(StandardCharsets.UTF_8);
        EncryptedMessage encryptedMessage = sessionCrypto.encrypt(currentPlainText);
        assertNotNull(encryptedMessage.getIV());
        assertNotNull(encryptedMessage.getCipherText());
        assertNotNull(encryptedMessage.getHmac());

        assertEquals(16, encryptedMessage.getIV().length);
        assertEquals(32, encryptedMessage.getHmac().length);
        assertTrue(encryptedMessage.getCipherText().length > 0);
    }

    @Test
    public void happyPathTest() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();
        KeyGenerator keyGenerator2 = KeyGenerator.getInstance("HmacSHA256");
        SecretKey hmacKey = keyGenerator2.generateKey();
        SessionCrypto sessionCrypto = new SessionCrypto(secretKey, hmacKey.getEncoded());
        byte[] currentPlainText = "hello world".getBytes(StandardCharsets.UTF_8);
        EncryptedMessage encryptedMessage = sessionCrypto.encrypt(currentPlainText);
        byte[] decryptedMessage = sessionCrypto.decrypt(encryptedMessage);
        assertNotNull(decryptedMessage);
        assertArrayEquals(currentPlainText, decryptedMessage);
    }

    @Test
    public void samePlainTextDifferentCipherText() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();
        KeyGenerator keyGenerator2 = KeyGenerator.getInstance("HmacSHA256");
        SecretKey hmacKey = keyGenerator2.generateKey();
        SessionCrypto sessionCrypto = new SessionCrypto(secretKey, hmacKey.getEncoded());
        byte[] currentPlainText = "hello world".getBytes(StandardCharsets.UTF_8);
        EncryptedMessage first = sessionCrypto.encrypt(currentPlainText);
        EncryptedMessage second = sessionCrypto.encrypt(currentPlainText);

        assertFalse(Arrays.equals(first.getIV(), second.getIV()));
        assertFalse(Arrays.equals(first.getCipherText(), second.getCipherText()));
    }

    @Test
    public void tamperedCipherText() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();
        KeyGenerator keyGenerator2 = KeyGenerator.getInstance("HmacSHA256");
        SecretKey hmacKey = keyGenerator2.generateKey();
        SessionCrypto sessionCrypto = new SessionCrypto(secretKey, hmacKey.getEncoded());
        byte[] currentPlainText = "attack simulation test".getBytes(StandardCharsets.UTF_8);
        EncryptedMessage encryptedMessage = sessionCrypto.encrypt(currentPlainText);
        byte[] tamperedCipherText = encryptedMessage.getCipherText().clone();
        tamperedCipherText[0] ^= 1;
        EncryptedMessage tamperedEncryptedMessage = new EncryptedMessage(
                encryptedMessage.getIV(),
                tamperedCipherText,
                encryptedMessage.getHmac()
        );
        assertThrows(SecurityException.class, () -> {
            sessionCrypto.decrypt(tamperedEncryptedMessage);
        });
    }
}
