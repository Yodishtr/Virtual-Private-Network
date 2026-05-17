import Network.HandShakeManager;
import encryption.EncryptedMessage;
import encryption.SessionCrypto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import protocol.MessageProtocol;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class HandshakeTest {

    @Test
    public void testHandshakeProcesses() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        ServerSocket serverSocket = new ServerSocket(8080);

        Future<SessionCrypto> serverTask = executor.submit((Callable<SessionCrypto>) () -> {
            try {
                Socket clientSocket = serverSocket.accept();
                InputStream propertiesStream = HandshakeTest.class.getClassLoader().
                        getResourceAsStream("server.properties");
                InputStream pkcsStream = HandshakeTest.class.getClassLoader().
                        getResourceAsStream("server-keystore.p12");
                Properties keyStoreProperties = new Properties();
                keyStoreProperties.load(propertiesStream);
                String keyAlias = keyStoreProperties.getProperty("server.keystore.alias");
                char[] privateKeyPassword = keyStoreProperties.getProperty("server.keystore.password").toCharArray();
                byte[] keyStorePassword = keyStoreProperties.getProperty("server.keystore.password").getBytes();
                // passed the input stream of the pkcs12 file to handshakeHandler object
                HandshakeHandler serverHandshakeHandler = new HandshakeHandler(clientSocket, keyAlias,
                        privateKeyPassword, pkcsStream, keyStorePassword);
                SessionCrypto serverSessionCrypto = serverHandshakeHandler.performHandshake();
                return serverSessionCrypto;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        });

        // client part
        Socket clientSocket = new Socket("localhost", 8080);
        HandShakeManager clientHandshakeManager = new HandShakeManager(clientSocket);
        SessionCrypto clientSessionCrypto = clientHandshakeManager.handleHandshake();
        SessionCrypto result = serverTask.get();
        Assertions.assertNotNull(result);
        Assertions.assertNotNull(clientSessionCrypto);

    }


    @Test
    public void testServerDecryption() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        ServerSocket serverSocket = new ServerSocket(8080);

        Future<String> serverTask = executor.submit((Callable<String>) () -> {
            try {
                Socket clientSocket = serverSocket.accept();
                InputStream propertiesStream = HandshakeTest.class.getClassLoader().
                        getResourceAsStream("server.properties");
                InputStream keystoreStream = HandshakeTest.class.getClassLoader().
                        getResourceAsStream("server-keystore.p12");
                Properties keyStoreProperties = new Properties();
                keyStoreProperties.load(propertiesStream);
                String keyAlias = keyStoreProperties.getProperty("server.keystore.alias");
                char[] privateKeyPassword = keyStoreProperties.getProperty("server.keystore.password").toCharArray();
                byte[] keyStorePassword = keyStoreProperties.getProperty("server.keystore.password").getBytes();
                HandshakeHandler serverHandshakeHandler = new HandshakeHandler(clientSocket, keyAlias,
                        privateKeyPassword, keystoreStream, keyStorePassword);
                SessionCrypto serverSessionCrypto = serverHandshakeHandler.performHandshake();
                InputStream serverInputStream = clientSocket.getInputStream();
                MessageProtocol.InboundMessage clientInboundingMessage = MessageProtocol.readMessage(serverInputStream);
                byte[] clientPayload = clientInboundingMessage.payload();
                EncryptedMessage receivedEncryptedMessage = EncryptedMessage.deserializeEncryptedMessage(clientPayload);
                String clientMessage = new String(serverSessionCrypto.decrypt(receivedEncryptedMessage),
                        StandardCharsets.UTF_8);
                return clientMessage;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        });

        // Client:
        Socket clientSocket = new Socket("localhost", 8080);
        HandShakeManager clientHandshakeManager = new HandShakeManager(clientSocket);
        SessionCrypto clientSessionCrypto = clientHandshakeManager.handleHandshake();
        EncryptedMessage encryptedClientMessage = clientSessionCrypto.encrypt("Hello".getBytes(StandardCharsets.UTF_8));
        OutputStream clientOutputStream = clientSocket.getOutputStream();
        Integer sendingHello = MessageProtocol.MessageType.DATA.getCode();
        byte[] serializedEncryptedHello = encryptedClientMessage.serializeEncryptedMessage();
        MessageProtocol.writeMessage(clientOutputStream, sendingHello.byteValue(), serializedEncryptedHello);
        String result = serverTask.get();
        Assertions.assertNotNull(result);
        Assertions.assertEquals("Hello", result);
    }


    @Test
    public void testClientDisconnectionRequest() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        ServerSocket serverSocket = new ServerSocket(8080);
        Future<String> serverTask = executor.submit((Callable<String>) () -> {
            try {
                Socket clientSocket = serverSocket.accept();
                InputStream propertiesStream = HandshakeTest.class.getClassLoader().
                        getResourceAsStream("server.properties");
                InputStream keystoreStream = HandshakeTest.class.getClassLoader().
                        getResourceAsStream("server-keystore.p12");
                Properties keyStoreProperties = new Properties();
                keyStoreProperties.load(propertiesStream);
                String keyAlias = keyStoreProperties.getProperty("server.keystore.alias");
                char[] privateKeyPassword = keyStoreProperties.getProperty("server.keystore.password").toCharArray();
                byte[] keyStorePassword = keyStoreProperties.getProperty("server.keystore.password").getBytes();
                HandshakeHandler serverHandshakeHandler = new HandshakeHandler(clientSocket, keyAlias,
                        privateKeyPassword, keystoreStream, keyStorePassword);
                SessionCrypto serverSessionCrypto = serverHandshakeHandler.performHandshake();
                ClientHandler clientHandler = new ClientHandler(clientSocket, serverSessionCrypto, UUID.randomUUID());
                clientHandler.run();
                return "Done";
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        });

        // Client
        Socket clientSocket = new Socket("localhost", 8080);
        HandShakeManager clientHandshakeManager = new HandShakeManager(clientSocket);
        SessionCrypto clientSessionCrypto = clientHandshakeManager.handleHandshake();
        OutputStream clientOutputStream = clientSocket.getOutputStream();
        InputStream clientInputStream = clientSocket.getInputStream();
        Integer disconnectionRequest = MessageProtocol.MessageType.DISCONNECT.getCode();
        MessageProtocol.writeMessage(clientOutputStream, disconnectionRequest.byteValue(), null);
        MessageProtocol.InboundMessage serverACK = MessageProtocol.readMessage(clientInputStream);
        byte[] serverAcknowledgement = serverACK.payload();
        EncryptedMessage receivedEncryptedMessage = EncryptedMessage.deserializeEncryptedMessage(serverAcknowledgement);
        byte[] decryptedServerACK = clientSessionCrypto.decrypt(receivedEncryptedMessage);
        String serverACKMessage = new String(decryptedServerACK, StandardCharsets.UTF_8);
        String result = serverTask.get();
        Assertions.assertNotNull(result);
        Assertions.assertEquals("Done", result);
        Assertions.assertEquals("SERVER_RECEIVED_DISCONNECTION_REQUEST", serverACKMessage);
    }
}
