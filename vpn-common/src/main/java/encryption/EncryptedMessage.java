package encryption;

public class EncryptedMessage {

    private byte[] IV;
    private byte[] cipherText;
    private byte[] hmac;

    public EncryptedMessage(byte[] IV, byte[] cipherText, byte[] hmac) {
        this.IV = IV;
        this.cipherText = cipherText;
        this.hmac = hmac;
    }

    // Getters
    public byte[] getIV() {
        return IV;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getHmac() {
        return hmac;
    }

    // Setters
    public void setIV(byte[] IV) {
        this.IV = IV;
    }

    public void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }

    public void setHmac(byte[] hmac) {
        this.hmac = hmac;
    }
}
