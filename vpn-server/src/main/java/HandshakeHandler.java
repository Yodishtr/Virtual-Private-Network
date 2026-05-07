import encryption.RSAUtil;
import encryption.SessionCrypto;
import protocol.MessageProtocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;

public class HandshakeHandler {

    private final Socket socket;

    public HandshakeHandler(Socket socket) {
        this.socket = socket;
    }

    public SessionCrypto performHandshake() throws IOException, UnrecoverableKeyException,
            CertificateException, KeyStoreException, NoSuchAlgorithmException {
        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();
        PrivateKey privateKey = RSAUtil.loadPrivateKey("vpn-server", "changeit".toCharArray());
        PublicKey publicKey = RSAUtil.loadPublicKey("vpn-server");
        int messageType = MessageProtocol.MessageType.SERVER_HELLO.ordinal();
    }
}
