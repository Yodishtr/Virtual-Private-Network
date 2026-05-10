package encryption;

import java.nio.ByteBuffer;

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


    // serializer
    public byte[] serializeEncryptedMessage() {
        Integer IntegerIVlength = this.IV.length;
        Integer IntegerCiphertextLength = this.cipherText.length;
        Integer IntegerHmacLength = this.hmac.length;

        byte[] serializedEncryptedMessage = ByteBuffer.allocate(12 + this.IV.length + this.cipherText.length +
                this.hmac.length)
                .putInt(IntegerIVlength)
                .put(this.IV)
                .putInt(IntegerCiphertextLength)
                .put(this.cipherText)
                .putInt(IntegerHmacLength)
                .put(this.hmac)
                .array();
        return serializedEncryptedMessage;
    }

    // deserializer
    public static EncryptedMessage deserializeEncryptedMessage(byte[] serializedEncryptedMessage) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(serializedEncryptedMessage);
        int ivLength = byteBuffer.getInt();
        if (ivLength == 0){
            throw new IllegalArgumentException("IV length must be greater than zero");
        }
        byte[] iv = new byte[ivLength];
        byteBuffer.get(iv, 0, iv.length);
        int cipherTextLength = byteBuffer.getInt();
        if (cipherTextLength == 0 || cipherTextLength >= serializedEncryptedMessage.length - (iv.length + 4)) {
            throw new IllegalArgumentException("cipherText length must be greater than zero");
        }
        byte[] cipherText = new byte[cipherTextLength];
        byteBuffer.get(cipherText, 0, cipherText.length);
        int hmacLength = byteBuffer.getInt();
        if (hmacLength == 0) {
            throw new IllegalArgumentException("hmac length must be greater than zero");
        }
        byte[] hmac = new byte[hmacLength];
        byteBuffer.get(hmac, 0, hmacLength);
        return new EncryptedMessage(iv, cipherText, hmac);
    }
}
