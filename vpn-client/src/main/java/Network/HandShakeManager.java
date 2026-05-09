package Network;

import encryption.SessionCrypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class HandShakeManager {

    private final Socket socket;

    public HandShakeManager(Socket socket) {
        this.socket = socket;
    }

    public SessionCrypto handleHandshake() throws IOException {
        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();

    }
}
