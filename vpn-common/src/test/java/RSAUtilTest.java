import encryption.RSAUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Map;

public class RSAUtilTest {

    private static PublicKey publicKey;
    private static PrivateKey privateKey;

    @BeforeAll
    static void keysSetUp() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    @Test
    void testGenerateRsaKeys() throws NoSuchAlgorithmException {
        Map<String, Key> rsaKeysMap = RSAUtil.generateRSAKeys(2048);
        Assertions.assertTrue(rsaKeysMap.containsKey("PublicKey"));
        Assertions.assertTrue(rsaKeysMap.containsKey("PrivateKey"));
        Assertions.assertNotNull(rsaKeysMap.get("PublicKey"));
        Assertions.assertNotNull(rsaKeysMap.get("PrivateKey"));
        Assertions.assertEquals("RSA", rsaKeysMap.get("PublicKey").getAlgorithm());
        Assertions.assertEquals("RSA", rsaKeysMap.get("PrivateKey").getAlgorithm());
    }

    @Test
    void testEncryptWithPublicKey() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] inputBytes = "20 years in the can. Not a peep!".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = RSAUtil.encryptWithPublicKey(inputBytes, publicKey);
        Assertions.assertNotNull(encryptedData);
        Assertions.assertFalse(Arrays.equals(inputBytes, encryptedData));
        Assertions.assertTrue(encryptedData.length > 0);
    }

    @Test
    void testDecryptWithPrivateKey() throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] inputBytes = "Whatever happened there?!".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = RSAUtil.encryptWithPublicKey(inputBytes, publicKey);
        byte[] decryptedData = RSAUtil.decryptWithPrivateKey(encryptedData, privateKey);
        Assertions.assertNotNull(decryptedData);
        Assertions.assertArrayEquals(inputBytes, decryptedData);
    }

    @Test
    void testDecryptingWithDiffPrivateKey() throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey diffPrivateKey = keyPair.getPrivate();
        byte[] inputBytes = "This mellifluous gift box".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = RSAUtil.encryptWithPublicKey(inputBytes, publicKey);
        try {
            byte[] decryptedData = RSAUtil.decryptWithPrivateKey(encryptedData, diffPrivateKey);
            Assertions.assertFalse(Arrays.equals(inputBytes, decryptedData));
        } catch (BadPaddingException e) {
            Assertions.assertTrue(true);
        }
    }

    // implement a test for the .p12 keystore. make a duplicate of it.

}
