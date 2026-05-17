import encryption.EncryptedMessage;
import encryption.SessionCrypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import protocol.MessageProtocol;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class ClientHandler implements Runnable{

    private static final Logger logger = LoggerFactory.getLogger(ClientHandler.class);

    private final Socket socket;
    private final SessionCrypto sessionCrypto;
    private final UUID sessionId;
    private boolean running;

    public ClientHandler(Socket socket, SessionCrypto sessionCrypto, UUID sessionId) {
        this.socket = socket;
        this.sessionCrypto = sessionCrypto;
        this.sessionId = sessionId;
        this.running = true;
    }

    @Override
    public void run() {
        try {
            readLoop();
        } catch (Exception e) {
            System.out.println("Client disconnected unexpectedly. Closing connection. Reason: " + e.getMessage());
        } finally {
            try {
                // mark session id as completed in the db later on
                this.socket.close();
                logger.info("Client requested disconnection for session id: " + sessionId);
            } catch (IOException e) {
                System.out.println("Unable to close socket connection: " + e.getMessage());
            }
        }
    }

    private void readLoop() throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();
        while (running) {
            MessageProtocol.InboundMessage inboundMessage = MessageProtocol.readMessage(inputStream);
            if (inboundMessage == null) {
                logger.error("inbound message is null");
                throw new IOException("Invalid message received");
            }
            if (inboundMessage.messageType() == MessageProtocol.MessageType.DATA.getCode()) {
                EncryptedMessage deserializedPayload = EncryptedMessage.
                        deserializeEncryptedMessage(inboundMessage.payload());
                byte[] decryptedPayload = this.sessionCrypto.decrypt(deserializedPayload);
                // maybe save to db for that session id? idk what to do with this decrypted plaintext
                byte[] serverResponse = "SERVER_RECEIVED_DATA".getBytes();
                EncryptedMessage encryptedMessage = this.sessionCrypto.encrypt(serverResponse);
                byte[] serializedEncryptedServerResponse = encryptedMessage.serializeEncryptedMessage();
                Integer serverDataMessageType = MessageProtocol.MessageType.DATA.getCode();
                MessageProtocol.writeMessage(outputStream, serverDataMessageType.byteValue(),
                        serializedEncryptedServerResponse);
            } else if (inboundMessage.messageType() == MessageProtocol.MessageType.DISCONNECT.getCode()) {
                byte[] serverResponse = "SERVER_RECEIVED_DISCONNECTION_REQUEST".getBytes();
                EncryptedMessage encryptedMessage = this.sessionCrypto.encrypt(serverResponse);
                byte[] serializedEncryptedServerResponse = encryptedMessage.serializeEncryptedMessage();
                Integer serverDataMessageType = MessageProtocol.MessageType.DATA.getCode();
                MessageProtocol.writeMessage(outputStream, serverDataMessageType.byteValue(),
                        serializedEncryptedServerResponse);
                this.running = false;
            } else {
                this.running = false;
                throw new IOException("Invalid protocol message received");
            }
        }
    }
}
