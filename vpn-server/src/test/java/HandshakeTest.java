import Network.HandShakeManager;
import encryption.SessionCrypto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;
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
                InputStream keyStoreStream = HandshakeTest.class.getClassLoader().
                        getResourceAsStream("server-keystore.p12");
                Properties keyStoreProperties = new Properties();
                keyStoreProperties.load(keyStoreStream);
                String keyAlias = keyStoreProperties.getProperty("server.keystore.alias");
                char[] privateKeyPassword = keyStoreProperties.getProperty("server.keystore.password").toCharArray();
                byte[] keyStorePassword = keyStoreProperties.getProperty("server.keystore.password").getBytes();
                HandshakeHandler serverHandshakeHandler = new HandshakeHandler(clientSocket, keyAlias,
                        privateKeyPassword, keyStoreStream, keyStorePassword);
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
        if (serverTask.isDone()) {
            Assertions.assertNotNull(serverTask.get());
            Assertions.assertNotNull(clientSessionCrypto);
        }

    }
}
