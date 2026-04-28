package encryption;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HMACUtil {

    public static byte[] deriveHMACKey(byte[] aesKeyBytes) throws NoSuchAlgorithmException,
            InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "HmacSHA256");
        hmac.init(secretKeySpec);
        byte[] label = "VPN_HMAC_KEY".getBytes(StandardCharsets.UTF_8);
        return hmac.doFinal(label);
    }

    public static byte[] computeHMAC(byte[] hmacKey, byte[] messageBytes) throws NoSuchAlgorithmException,
            InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(hmacKey, "HmacSHA256");
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(secretKeySpec);
        byte[] hmacBytes = hmac.doFinal(messageBytes);
        return hmacBytes;
    }

    public static boolean verifyHMAC(byte[] hmacKey, byte[] messageBytes, byte[] signatureBytes) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(hmacKey, "HmacSHA256");
            hmac.init(secretKeySpec);
            byte[] computedHmac = hmac.doFinal(messageBytes);
            return MessageDigest.isEqual(computedHmac, signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            return false;
        }
    }
}
