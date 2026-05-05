import encryption.EncryptedMessage;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;

public class EncryptedMessageTest {
    byte[] myIV;
    byte[] cipherText;
    byte[] hmac;

    @BeforeEach
    public void setup() {
        myIV = "Ooof Maddone".getBytes(StandardCharsets.UTF_8);
        cipherText = "Whaddaya Hear whaddaya say".getBytes(StandardCharsets.UTF_8);
        hmac = "I like the one that says shum pulp".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void testConstructor() {
        EncryptedMessage encryptedMessage = new EncryptedMessage(myIV, cipherText, hmac);
        Assertions.assertArrayEquals(myIV, encryptedMessage.getIV());
        Assertions.assertArrayEquals(cipherText, encryptedMessage.getCipherText());
        Assertions.assertArrayEquals(hmac, encryptedMessage.getHmac());
    }

    @Test
    public void testSetters() {
        EncryptedMessage encryptedMessage = new EncryptedMessage(myIV, cipherText, hmac);
        byte[] ricchione = "You knew Vito was a ricchione?".getBytes(StandardCharsets.UTF_8);
        byte[] justaRacket = "you schifooz".getBytes(StandardCharsets.UTF_8);
        byte[] parakeet = "EHH you look like you were in Miami".getBytes(StandardCharsets.UTF_8);
        encryptedMessage.setIV(ricchione);
        encryptedMessage.setCipherText(justaRacket);
        encryptedMessage.setHmac(parakeet);
        Assertions.assertArrayEquals(ricchione, encryptedMessage.getIV());
        Assertions.assertArrayEquals(justaRacket, encryptedMessage.getCipherText());
        Assertions.assertArrayEquals(parakeet, encryptedMessage.getHmac());
    }

}
