import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ServerMain {

    private Properties config;
    private int port;
    private boolean running;
    private ServerSocket serverSocket;
    private ExecutorService executor;

    public ServerMain(Properties config) throws IOException {
        this.config = config;
    }

    private Properties loadConfig() {
        Properties currentProps = new Properties();
        try (InputStream serverPropsFile = getClass().getClassLoader().getResourceAsStream("server.properties")) {
            if (serverPropsFile == null) {
                throw new IOException("server properties file not found");
            }
            currentProps.load(serverPropsFile);
            return currentProps;
        } catch (IOException e){
            e.printStackTrace();
            return currentProps;
        }
    }

    private void handleClient(Socket socket) {
        InputStream keyStoreStream = ServerMain.class.getResourceAsStream("server-keystore.p12");
        HandshakeHandler currentHandshakeHandler = new HandshakeHandler(socket,
                this.config.getProperty("server.keystore.alias"), "changeit".toCharArray(), keyStoreStream,
                "changeit".getBytes(StandardCharsets.UTF_8));
    }

    private void start() {
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
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {

    }
}
