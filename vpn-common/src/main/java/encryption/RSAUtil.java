package encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class RSAUtil {

    private static final Logger logger = LoggerFactory.getLogger(RSAUtil.class);

    public static Map<String, Key> generateRSAKeys(int keySize) throws NoSuchAlgorithmException {
        Map<String, Key> keysMap = new HashMap<>();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        keysMap.put("PublicKey", publicKey);
        keysMap.put("PrivateKey", privateKey);

        String publicBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        logger.info("Public key: {}", publicBase64);
        logger.info("Private key: {}", privateBase64);
        return keysMap;
    }

    public static byte[] encryptWithPublicKey(String message, PublicKey publicKey) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String cipherTransformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        byte[] inputBytes = message.getBytes();
        Cipher encryptCipher = Cipher.getInstance(cipherTransformation);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = encryptCipher.doFinal(inputBytes);
        return encryptedData;
    }

    public static byte[] decryptWithPrivateKey(byte[] encryptedData, PrivateKey privateKey) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String cipherTransformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        Cipher decryptCipher = Cipher.getInstance(cipherTransformation);
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decryptCipher.doFinal(encryptedData);
    }

    public static void saveKey(Key key, String keyAlias, String keyPassword) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream inputStream = new FileInputStream("vpn-server/src/main/resources/server-keystore");
        // need to create a class to load server.properties
        ks.load(inputStream, "changeit".toCharArray());
        ks.setKeyEntry(keyAlias, key.getEncoded(), null);
        try (FileOutputStream outputStream = new FileOutputStream("vpn-server/src/main/resources/server-keystore")) {
            ks.store(outputStream, "changeit".toCharArray());
        }
    }


}
