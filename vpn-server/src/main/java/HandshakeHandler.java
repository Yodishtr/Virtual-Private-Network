import encryption.HMACUtil;
import encryption.RSAUtil;
import encryption.SessionCrypto;
import protocol.MessageProtocol;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;

public class HandshakeHandler {

    private final Socket socket;

    public HandshakeHandler(Socket socket) {
        this.socket = socket;
    }

    public SessionCrypto performHandshake() throws IOException, UnrecoverableKeyException,
            CertificateException, KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();
        PrivateKey privateKey = RSAUtil.loadPrivateKey("vpn-server", "changeit".toCharArray());
        PublicKey publicKey = RSAUtil.loadPublicKey("vpn-server");
        byte[] encodedPublicKey = publicKey.getEncoded();
        Integer messageType = MessageProtocol.MessageType.SERVER_HELLO.ordinal();
        MessageProtocol.writeMessage(outputStream, messageType.byteValue(), encodedPublicKey);
        MessageProtocol.InboundMessage inboundMessage = MessageProtocol.readMessage(inputStream);
        // will only have the aesKey in the inboundMessage then use the hmacUtil to derive the hmac key
        if (inboundMessage.messageType() != MessageProtocol.MessageType.KEY_EXCHANGE.ordinal()) {
            throw new IOException("Invalid message type: " + inboundMessage.messageType());
        }
        byte[] inboundMessagePayload = inboundMessage.payload();
        byte[] decryptedInboundPayload = RSAUtil.decryptWithPrivateKey(inboundMessagePayload, privateKey);
        SecretKey aesKey = new SecretKeySpec(decryptedInboundPayload, "AES");
        byte[] derivedHmacKey = HMACUtil.deriveHMACKey(aesKey.getEncoded());
        SessionCrypto sessionCrypto = new SessionCrypto(aesKey, derivedHmacKey);
        Integer handshakeOkMessage = MessageProtocol.MessageType.HANDSHAKE_OK.ordinal();
        MessageProtocol.writeMessage(outputStream, handshakeOkMessage.byteValue(),
                "VPN_HANDSHAKE_OK".getBytes(StandardCharsets.UTF_8));
        return sessionCrypto;
    }
}
