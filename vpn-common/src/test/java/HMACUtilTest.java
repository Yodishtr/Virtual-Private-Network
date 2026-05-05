import encryption.HMACUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMACUtilTest {

    @Test
    void testDeriveHmacKey() throws NoSuchAlgorithmException, InvalidKeyException {
        // AES Key Generation for this method
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey aesKey = aesKeyGen.generateKey();
        byte[] aesKeyArray = aesKey.getEncoded();

        // hmac key testing
        byte[] derivedHmacKey = HMACUtil.deriveHMACKey(aesKeyArray);
        Assertions.assertNotNull(derivedHmacKey);
        Assertions.assertEquals(32, derivedHmacKey.length);
    }

    @Test
    void testComputeHmacKeySameMessageSoSameHmac() throws NoSuchAlgorithmException, InvalidKeyException {

    }

    @Test
    void testComputeHmacKeyDiffMessageDiffHmac() throws NoSuchAlgorithmException, InvalidKeyException {
        // same key + same message gives same HMAC
        // same key + different message gives different HMAC
    }

    @Test
    void testVerifyHmacKey() throws NoSuchAlgorithmException, InvalidKeyException {
        // returns true for correct key, message, and signature
        // returns false if message is changed
        // returns false if signature is changed
        // returns false if key is wrong
    }
}
