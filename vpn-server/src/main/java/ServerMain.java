import encryption.SessionCrypto;

import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ServerMain {

    private Properties config;
    private int port;
    private boolean running;
    private ServerSocket serverSocket;
    private ExecutorService executor;

    public ServerMain(Properties config) {
        this.config = config;
        this.port = Integer.parseInt(this.config.getProperty("server.port"));
    }

    public ServerMain() {}

    public static Properties loadConfig() throws IOException {
        Properties config = new Properties();
        InputStream serverPropsFile = ServerMain.class.getClassLoader().getResourceAsStream("server.properties");
        if (serverPropsFile == null) {
            throw new IOException("server properties file not found");
        }
        config.load(serverPropsFile);
        serverPropsFile.close();
        return config;
    }

    public void shutdown() {
        this.running = false;
        if (this.serverSocket != null) {
            try {
                this.serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (this.executor != null) {
            this.executor.shutdown();
        }
    }

    public void handleClient(Socket socket) {
        InputStream keyStoreStream = getClass().getClassLoader().getResourceAsStream("server-keystore.p12");
        if (keyStoreStream == null) {
            System.out.println("server-keystore.p12 not found");
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return;
        }
        HandshakeHandler currentHandshakeHandler = new HandshakeHandler(socket,
                this.config.getProperty("server.keystore.alias"), this.config.getProperty("server.keystore.password").toCharArray(),
                keyStoreStream, this.config.getProperty("server.keystore.password").getBytes(StandardCharsets.UTF_8));
        try {
            SessionCrypto encryptedSession = currentHandshakeHandler.performHandshake();
            UUID tempSessionId = UUID.randomUUID();
            ClientHandler clientHandler = new ClientHandler(socket, encryptedSession, tempSessionId);
            clientHandler.run();
        } catch (IOException e) {
            e.printStackTrace();
            try {
                socket.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }

    public void start() {
        try {
            this.serverSocket = new ServerSocket(this.port);
            this.running = true;
            this.executor = Executors.newVirtualThreadPerTaskExecutor();
            System.out.println("Server started on port " + this.port);
            while (this.running) {
                Socket socket = this.serverSocket.accept();
                this.executor.submit(() -> handleClient(socket));
            }

        } catch (IOException e) {
            if (this.running) {
                System.out.println("Accept method failed unexpectedly");
            } else {
                System.out.println("Server shutdown...");
            }
        }
    }



    // Getters
    public Properties getConfig() {
        return this.config;
    }

    public int getPort() {
        return this.port;
    }

    public boolean isRunning() {
        return this.running;
    }

    public ServerSocket getServerSocket() {
        return this.serverSocket;
    }

    public ExecutorService getExecutor() {
        return this.executor;
    }

    // Setters
    public void setConfig(Properties config) {
        this.config = config;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setRunning(boolean running) {
        this.running = running;
    }

    public void setServerSocket(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }

    public void setExecutor(ExecutorService executor) {
        this.executor = executor;
    }

    public static void main(String[] args) throws IOException {
        Properties currentConfig = loadConfig();
        ServerMain server = new ServerMain(currentConfig);
        server.start();
        System.out.println("Server connection severed.");
    }
}
