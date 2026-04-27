package encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class RSAUtil {

    public static Map<String, Key> generateRSAKeys(int keySize) throws NoSuchAlgorithmException {
        Map<String, Key> keysMap = new HashMap<>();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        keysMap.put("PublicKey", publicKey);
        keysMap.put("PrivateKey", privateKey);
        return keysMap;
    }

    public static byte[] encryptWithPublicKey(byte[] inputBytes, PublicKey publicKey) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String cipherTransformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
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

    public static PrivateKey loadPrivateKey(String keyAlias, char[] keyPassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream inputStream = RSAUtil.class.getClassLoader().
                getResourceAsStream("server-keystore.p12")) {
            if (inputStream == null) {
                throw new RuntimeException("server-keystore.p12 not found");
            }
            char[] keystorePassword = "changeit".toCharArray();
            keyStore.load(inputStream, keystorePassword);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword);
            return privateKey;
        }
    }

    public static PublicKey loadPublicKey(String keyAlias) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream inputStream = RSAUtil.class.getClassLoader().getResourceAsStream("server-keystore.p12")) {
            if (inputStream == null) {
                throw new RuntimeException("server-keystore.p12 not found");
            }
            char[] keystorePassword = "changeit".toCharArray();
            keyStore.load(inputStream, keystorePassword);
            Certificate certificate = keyStore.getCertificate(keyAlias);
            if (certificate == null) {
                throw new RuntimeException("certificate not found");
            }
            PublicKey publicKey = certificate.getPublicKey();
            return publicKey;

        }
    }
}
