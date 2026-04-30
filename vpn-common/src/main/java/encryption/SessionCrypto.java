package encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionCrypto {

    private final SecretKey aesKey;
    private final byte[] hmacKey;

    public SessionCrypto(SecretKey aesKey, byte[] hmacKey) {
        if (aesKey == null || hmacKey == null) {
            throw new IllegalArgumentException("AES key and HMAC key cannot be null");
        }
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
    }

    public EncryptedMessage encrypt(byte[] plainText) throws InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException {
        if (plainText == null) {
            throw new IllegalArgumentException("Plaintext cannot be null");
        }
        byte[] generatedIV = AESUtil.generateIv();
        byte[] cipherText = AESUtil.encryptPlainText(plainText, this.aesKey, generatedIV);
        // should concatenate the IV and the cipherText before computing the hmac tag/signature
        byte[] concatenatedBytes = concatenateByteArrays(generatedIV, cipherText);
        byte[] hmacTag = HMACUtil.computeHMAC(this.hmacKey, concatenatedBytes);
        return new EncryptedMessage(generatedIV, cipherText, hmacTag);
    }

    public byte[] decrypt(EncryptedMessage encryptedMessage) throws InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException {
        if (encryptedMessage.getIV() == null || encryptedMessage.getCipherText() == null ||
                encryptedMessage.getHmac() == null) {
            throw new IllegalArgumentException("Message is malformed");
        }
        byte[] cipherText = encryptedMessage.getCipherText();
        byte[] hmacTag = encryptedMessage.getHmac();
        byte[] authenticatedData = concatenateByteArrays(encryptedMessage.getIV(), cipherText);
        boolean accepted = HMACUtil.verifyHMAC(this.hmacKey, authenticatedData, hmacTag);
        if (!accepted) {
            throw new SecurityException("HMAC verification failed");
        }
        byte[] decryptedCipherText = AESUtil.decryptCipherText(cipherText, this.aesKey, encryptedMessage.getIV());
        return decryptedCipherText;
    }

    private byte[] concatenateByteArrays(byte[] IV, byte[] cipherText) {
        byte[] combined = ByteBuffer.allocate(IV.length + cipherText.length)
                .put(IV)
                .put(cipherText)
                .array();
        return combined;
    }
}
