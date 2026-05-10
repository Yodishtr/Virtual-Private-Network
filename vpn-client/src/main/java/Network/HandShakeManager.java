package Network;

import encryption.AESUtil;
import encryption.HMACUtil;
import encryption.RSAUtil;
import encryption.SessionCrypto;
import protocol.MessageProtocol;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class HandShakeManager {

    private final Socket socket;

    public HandShakeManager(Socket socket) {
        this.socket = socket;
    }

    public SessionCrypto handleHandshake() throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException {
        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();
        MessageProtocol.InboundMessage firstServerMessage = MessageProtocol.readMessage(inputStream);
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
        if (handshakeSuccessCode == MessageProtocol.MessageType.HANDSHAKE_ERROR.getCode()){
            throw new IOException("Handshake error");
        }
        SessionCrypto clientSessionCrypto = new SessionCrypto(aesKey, hmacKey);

    }
}
