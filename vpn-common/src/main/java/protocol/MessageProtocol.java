package protocol;

import java.io.*;
import java.nio.ByteBuffer;

public class MessageProtocol {

    public enum MessageType {
        SERVER_HELLO(1),
        KEY_EXCHANGE(2),
        HANDSHAKE_OK(3),
        HANDSHAKE_ERROR(4),
        DATA(5),
        DISCONNECT(6);

        private final int code;

        private MessageType(int code) {
            this.code = code;
        }
    }

    public record InboundMessage(byte messageType, byte[] payload) {}

    public static void writeMessage(OutputStream out, byte messageType, byte[] payload) throws IOException {
        if (payload == null) {
            payload = new byte[0];
        }
        int payloadLength = payload.length;
        DataOutputStream byteArrayConcatenator = new DataOutputStream(out);
        byteArrayConcatenator.writeByte(messageType);
        byteArrayConcatenator.writeInt(payloadLength);
        byteArrayConcatenator.write(payload);
        byteArrayConcatenator.flush();
    }

    public static InboundMessage readMessage(InputStream input) throws IOException {
        DataInputStream dataInputStream = new DataInputStream(input);
        byte messageTypeByte = dataInputStream.readByte();
        int payloadLength = dataInputStream.readInt();
        if (payloadLength < 0 || payloadLength > 1024L * 1024L) {
            throw new IOException("Invalid message length");
        }
        byte[] payload = new byte[payloadLength];
        dataInputStream.readFully(payload);
        return new InboundMessage(messageTypeByte, payload);
    }
}
