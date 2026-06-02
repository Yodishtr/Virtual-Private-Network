package db;

import utilities.Session;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

public interface SessionRepo {

    Optional<Session> createNewSession(long userId, String clientIp);

    Optional<Session> updateDisconnectSessionTimeAndReason(String reason, long sessionId);

    Optional<Session> updateBytesTransferred(long byteSent, long byteReceived, long sessionId);

    List<Session> findActiveSessions();

    int countActiveSessions();

    List<Session> findUserSessions(String username);
}
