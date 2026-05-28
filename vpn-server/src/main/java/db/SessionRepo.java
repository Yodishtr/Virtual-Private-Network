package db;

import utilities.Session;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

public interface SessionRepo {

    long createNewSession(long userId, String clientIp);

    Optional<Session> updateDisconnectSessionTimeAndReason(String reason, long sessionId);

    boolean updateBytesTransferred(long bytesTransferred);

    List<Session> findActiveSessions();

    List<Session> findUserSessions(String username);
}
