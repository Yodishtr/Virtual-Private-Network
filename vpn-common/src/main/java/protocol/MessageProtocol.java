package protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;

public class MessageProtocol {

    record InBoundMessage(byte messageType, byte[] payload) {}

    public static void writeMessage(OutputStream out, byte messageType, byte[] payload) throws IOException {
        int payloadLength = payload.length;
        byte[] messagePayloadLength = ByteBuffer.allocate(4).putInt(payloadLength).array();
        ByteArrayOutputStream byteArrayConcatenator = new ByteArrayOutputStream();
        byteArrayConcatenator.write(messageType);
        byteArrayConcatenator.write(messagePayloadLength);
        byteArrayConcatenator.write(payload);
        byte[] outboundMessage = byteArrayConcatenator.toByteArray();
        out.write(outboundMessage);
    }

    public static InBoundMessage readMessage(InputStream input) throws IOException {
        int messageType = input.read();
        if (messageType == -1){
            throw new ClosedChannelException();
        }
        byte[] lengthBytes = new byte[4];
        int i = 0;
        while (i < 4) {

            i++;
        }
    }
}
