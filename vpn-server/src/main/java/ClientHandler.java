import encryption.SessionCrypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.UUID;

public class ClientHandler implements Runnable{

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
            } catch (IOException e) {
                System.out.println("Unable to close socket connection: " + e.getMessage());
            }
        }
    }

    private void readLoop() throws IOException {
        while (running) {
            InputStream inputStream = socket.getInputStream();
            OutputStream outputStream = socket.getOutputStream();

        }
    }
}
