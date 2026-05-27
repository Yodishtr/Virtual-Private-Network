package utilities;

import java.time.Instant;
import java.util.UUID;

public class Session {

    private long id;
    private long userId;
    private String clientIp;
    private Instant createdAt;
    private Instant disconnectedAt;
    private long bytesSent;
    private long bytesReceived;
    private String disconnectReason;
    private UUID sessionToken;

    public Session(long id, long userId, String clientIp, Instant createdAt, Instant disconnectedAt, long bytesSent,
                   long bytesReceived, String disconnectReason, UUID sessionToken) {
        this.id = id;
        this.userId = userId;
        this.clientIp = clientIp;
        this.createdAt = createdAt;
        this.disconnectedAt = disconnectedAt;
        this.bytesSent = bytesSent;
        this.bytesReceived = bytesReceived;
        this.disconnectReason = disconnectReason;
        this.sessionToken = sessionToken;
    }

    // Getters
    public long getId() {
        return id;
    }

    public long getUserId() {
        return userId;
    }

    public String getClientIp() {
        return clientIp;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getDisconnectedAt() {
        return disconnectedAt;
    }

    public long getBytesSent() {
        return bytesSent;
    }

    public long getBytesReceived() {
        return bytesReceived;
    }

    public String getDisconnectReason() {
        return disconnectReason;
    }

    public UUID getSessionToken() {
        return sessionToken;
    }

    // Setters
    public void setId(long id) {
        this.id = id;
    }

    public void setUserId(long userId) {
        this.userId = userId;
    }

    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public void setDisconnectedAt(Instant disconnectedAt) {
        this.disconnectedAt = disconnectedAt;
    }

    public void setBytesSent(long bytesSent) {
        this.bytesSent = bytesSent;
    }

    public void setBytesReceived(long bytesReceived) {
        this.bytesReceived = bytesReceived;
    }

    public void setDisconnectReason(String disconnectReason) {
        this.disconnectReason = disconnectReason;
    }

    public void setSessionToken(UUID sessionToken) {
        this.sessionToken = sessionToken;
    }
}
