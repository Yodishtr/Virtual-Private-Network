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

        byte IVlength = IntegerIVlength.byteValue();
        byte cipherTextLength = IntegerCiphertextLength.byteValue();
        byte hmacLength = IntegerHmacLength.byteValue();

        byte[] IVlengthArray = new byte[1];
        IVlengthArray[0] = IVlength;
        byte[] cipherTextLengthArray = new byte[1];
        cipherTextLengthArray[0] = cipherTextLength;
        byte[] hmacLengthArray = new byte[1];
        hmacLengthArray[0] = hmacLength;

        byte[] serializedEncryptedMessage = ByteBuffer.allocate(IVlengthArray.length +
                cipherTextLengthArray.length + hmacLengthArray.length + this.IV.length + this.cipherText.length +
                this.hmac.length)
                .put(IVlengthArray)
                .put(this.IV)
                .put(cipherTextLengthArray)
                .put(this.cipherText)
                .put(hmacLengthArray)
                .put(this.hmac)
                .array();
        return serializedEncryptedMessage;
    }


}
