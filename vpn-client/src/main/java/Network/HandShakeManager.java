package Network;

import encryption.*;
import protocol.MessageProtocol;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class HandShakeManager {

    private final Socket socket;

    public HandShakeManager(Socket socket) {
        this.socket = socket;
    }

    public SessionCrypto handleHandshake() throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();
        MessageProtocol.InboundMessage firstServerMessage = MessageProtocol.readMessage(inputStream);
        if (firstServerMessage.messageType() != MessageProtocol.MessageType.SERVER_HELLO.getCode()){
            throw new IllegalArgumentException("Invalid message received");
        }
        byte[] publicKeyArray = firstServerMessage.payload();
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKeyArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey currentPublicKey = keyFactory.generatePublic(encodedKeySpec);
        SecretKey aesKey = AESUtil.generateAesKey();
        byte[] hmacKey = HMACUtil.deriveHMACKey(aesKey.getEncoded());
        byte[] encryptedAesPayload = RSAUtil.encryptWithPublicKey(aesKey.getEncoded(), currentPublicKey);
        Integer keyExchangeMessageType = MessageProtocol.MessageType.KEY_EXCHANGE.getCode();
        MessageProtocol.writeMessage(outputStream, keyExchangeMessageType.byteValue(), encryptedAesPayload);
        MessageProtocol.InboundMessage serverMessage = MessageProtocol.readMessage(inputStream);
        Integer handshakeSuccessCode = serverMessage.messageType();
        if (handshakeSuccessCode == MessageProtocol.MessageType.HANDSHAKE_ERROR.getCode() || handshakeSuccessCode !=
                MessageProtocol.MessageType.HANDSHAKE_OK.getCode()){
            throw new IOException("Handshake error");
        }
        SessionCrypto clientSessionCrypto = new SessionCrypto(aesKey, hmacKey);
        byte[] inboundMessagePayload = serverMessage.payload();
        EncryptedMessage encryptedMessage = EncryptedMessage.deserializeEncryptedMessage(inboundMessagePayload);
        String receivedString = new String(clientSessionCrypto.decrypt(encryptedMessage), StandardCharsets.UTF_8);
        if (!receivedString.equals("VPN_HANDSHAKE_OK")){
            throw new IOException("Handshake error");
        }
        return clientSessionCrypto;
    }
}
