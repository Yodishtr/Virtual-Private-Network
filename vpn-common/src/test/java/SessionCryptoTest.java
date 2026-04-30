import encryption.AESUtil;
import encryption.HMACUtil;
import encryption.SessionCrypto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionCryptoTest {

    private SessionCrypto sessionCrypto;
    private SecretKey aesSecretKey;
    private byte[] hmacKey;

    @BeforeEach
    public void setUp() throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKey aesKey = AESUtil.generateAesKey();
        this.aesSecretKey = aesKey;
        byte[] hmacKey = HMACUtil.deriveHMACKey(aesKey.getEncoded());
        this.hmacKey = hmacKey;
        SessionCrypto sessionCrypto = new SessionCrypto(aesKey, hmacKey);
        this.sessionCrypto = sessionCrypto;
    }


    // cehck if returns original plaintext
    @Test
    public void encryptThenDecrypt() {
        byte[] plainText = "hello world".getBytes(StandardCharsets.UTF_8);

    }
}
