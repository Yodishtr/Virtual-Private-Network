import encryption.HMACUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HMACUtilTest {

    private SecretKey aesKey;

    @BeforeEach
    void setAesKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        aesKey = keyGenerator.generateKey();
    }

    @Test
    void testDeriveHmacKey() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] aesKeyArray = aesKey.getEncoded();

        // hmac key testing
        byte[] derivedHmacKey = HMACUtil.deriveHMACKey(aesKeyArray);
        Assertions.assertNotNull(derivedHmacKey);
        Assertions.assertEquals(32, derivedHmacKey.length);
    }

    @Test
    void testComputeHmacKeySameMessageSoSameHmac() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] aesKeyArray = aesKey.getEncoded();
        byte[] derivedHmacKey = HMACUtil.deriveHMACKey(aesKeyArray);

        byte[] inputText = "hes a married man. with a GOOMAR!".getBytes(StandardCharsets.UTF_8);
        byte[] firstResult = HMACUtil.computeHMAC(derivedHmacKey, inputText);
        byte[] secondResult = HMACUtil.computeHMAC(derivedHmacKey, inputText);
        Assertions.assertArrayEquals(firstResult, secondResult);
    }

    @Test
    void testComputeHmacKeyDiffMessageDiffHmac() throws NoSuchAlgorithmException, InvalidKeyException {
        // same key + same message gives same HMAC
        // same key + different message gives different HMAC
        byte[] aesKeyArray = aesKey.getEncoded();
        byte[] derivedHmacKey = HMACUtil.deriveHMACKey(aesKeyArray);

        byte[] inputTextFirst = "hes a married man. with a GOOMAR!".getBytes(StandardCharsets.UTF_8);
        byte[] inputTextSecond = "Think Burger boy!".getBytes(StandardCharsets.UTF_8);
        byte[] firstResult = HMACUtil.computeHMAC(derivedHmacKey, inputTextFirst);
        byte[] secondResult = HMACUtil.computeHMAC(derivedHmacKey, inputTextSecond);
        Assertions.assertFalse(Arrays.equals(firstResult, secondResult));
    }

    @Test
    void testVerifyHmacKey() throws NoSuchAlgorithmException, InvalidKeyException {
        // returns true for correct key, message, and signature
        // returns false if message is changed
        // returns false if signature is changed
        // returns false if key is wrong
        byte[] hmacKey = "Random hmac key".getBytes(StandardCharsets.UTF_8);
        byte[] message = "Nice Rack!".getBytes(StandardCharsets.UTF_8);
        byte[] validSignature = HMACUtil.computeHMAC(hmacKey, message);
        boolean isValid = HMACUtil.verifyHMAC(hmacKey, message, validSignature);
        Assertions.assertTrue(isValid);
    }
}
