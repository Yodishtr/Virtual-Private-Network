import encryption.EncryptedMessage;
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
    private final String keyAlias;
    private final char[] privateKeyPassword;
    private final InputStream keyStoreStream;
    private final byte[] keyStorePassword;

    public HandshakeHandler(Socket socket, String keyAlias, char[] privateKeyPassword, InputStream keyStoreStream,
                            byte[] keyStorePassword) {
        this.socket = socket;
        this.keyAlias = keyAlias;
        this.privateKeyPassword = privateKeyPassword;
        this.keyStoreStream = keyStoreStream;
        this.keyStorePassword = keyStorePassword;
    }

    public SessionCrypto performHandshake() throws IOException {
        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();
        try {
            PrivateKey privateKey = RSAUtil.loadPrivateKey(this.keyAlias, this.privateKeyPassword,
                    this.keyStoreStream, this.keyStorePassword);
            PublicKey publicKey = RSAUtil.loadPublicKey(this.keyAlias, this.keyStoreStream, this.keyStorePassword);
            byte[] encodedPublicKey = publicKey.getEncoded();
            Integer messageType = MessageProtocol.MessageType.SERVER_HELLO.getCode();
            MessageProtocol.writeMessage(outputStream, messageType.byteValue(), encodedPublicKey);
            MessageProtocol.InboundMessage inboundMessage = MessageProtocol.readMessage(inputStream);
            // will only have the aesKey in the inboundMessage then use the hmacUtil to derive the hmac key
            if (inboundMessage.messageType() != MessageProtocol.MessageType.KEY_EXCHANGE.getCode()) {
                throw new IOException("Invalid message type: " + inboundMessage.messageType());
            }
            byte[] inboundMessagePayload = inboundMessage.payload();
            byte[] decryptedInboundPayload = RSAUtil.decryptWithPrivateKey(inboundMessagePayload, privateKey);
            if (decryptedInboundPayload.length != 32 ) {
                throw new IOException("Invalid message payload");
            }
            SecretKey aesKey = new SecretKeySpec(decryptedInboundPayload, "AES");
            byte[] derivedHmacKey = HMACUtil.deriveHMACKey(aesKey.getEncoded());
            SessionCrypto sessionCrypto = new SessionCrypto(aesKey, derivedHmacKey);
            Integer handshakeOkMessage = MessageProtocol.MessageType.HANDSHAKE_OK.getCode();
            EncryptedMessage encryptedHandshakeOK = sessionCrypto.encrypt(
                    "VPN_HANDSHAKE_OK".getBytes(StandardCharsets.UTF_8));
            byte[] serializedEncryptedMessage = encryptedHandshakeOK.serializeEncryptedMessage();
            MessageProtocol.writeMessage(outputStream, handshakeOkMessage.byteValue(), serializedEncryptedMessage);
            return sessionCrypto;
        } catch (IOException | UnrecoverableKeyException | CertificateException | KeyStoreException |
                NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
        InvalidKeyException | InvalidAlgorithmParameterException e) {
            try {
                Integer handshakeErrorType = MessageProtocol.MessageType.HANDSHAKE_ERROR.getCode();
                MessageProtocol.writeMessage(outputStream, handshakeErrorType.byteValue(),
                        "Encrypted session unable to be established".getBytes(StandardCharsets.UTF_8));
            } catch (IOException ioException) {
                throw new IOException(ioException);
            }
            // should throw an exception since catch clause wont return anything.
            throw new IOException("encrypted session could not be established.", e);
        }
    }
}
