package db;

import com.zaxxer.hikari.HikariDataSource;
import utilities.Session;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class SessionRepository implements SessionRepo {

    private final HikariDataSource dataSource;

    public SessionRepository(HikariDataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public long createNewSession(long userId, String clientIp) {
        String insertSqlStatement = "INSERT INTO sessions (user_id, client_ip, session_token) VALUES (?, ?, ?)";
        try (Connection connection = this.dataSource.getConnection();
        PreparedStatement preparedStatement = connection.prepareStatement(insertSqlStatement)) {
            preparedStatement.setLong(1, userId);
            preparedStatement.setString(2, clientIp);
            UUID sessionToken = UUID.randomUUID();
            preparedStatement.setObject(3, sessionToken);
            int insertionResult = preparedStatement.executeUpdate();
            if (insertionResult == 1) {
                String selectSqlStatement = "SELECT * FROM sessions WHERE session_token = ?";
                try (PreparedStatement selectStatement = connection.prepareStatement(selectSqlStatement)) {
                    selectStatement.setObject(1, sessionToken);
                    ResultSet resultSet = selectStatement.executeQuery();
                    if (resultSet.next()) {
                        long sessionId =  resultSet.getLong("id");
                        return sessionId;
                    } else {
                        return -1;
                    }
                } catch (SQLException e){
                    e.printStackTrace();
                }
            } else {
                return -1;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }

    @Override
    public Optional<Session> updateDisconnectSessionTimeAndReason(String reason, long sessionId) {
        String updateSqlStatement = "UPDATE sessions SET disconnect_reason = ?," +
                " disconnected_at = NOW() WHERE id = ? RETURNING *";
        try (Connection connection = this.dataSource.getConnection();
        PreparedStatement preparedStatement = connection.prepareStatement(updateSqlStatement)) {
            preparedStatement.setString(1, reason);
            preparedStatement.setLong(2, sessionId);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    long userID = resultSet.getLong("user_id");
                    String clientIp = resultSet.getObject("client_ip").toString();
                    OffsetDateTime connectedAt = resultSet.getObject("connected_at", OffsetDateTime.class);
                    OffsetDateTime disconnectAt = resultSet.getObject("disconnect_at", OffsetDateTime.class);
                    long bytesSent = resultSet.getLong("bytes_sent");
                    long bytesReceived = resultSet.getLong("bytes_received");
                    UUID sessionToken = resultSet.getObject("session_token", UUID.class);
                    Session currentSessionUpdated = new Session(sessionId, userID, clientIp, connectedAt, disconnectAt,
                            bytesSent, bytesReceived, reason, sessionToken);
                    return Optional.of(currentSessionUpdated);
                } else {
                    return Optional.empty();
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }

    @Override
    public boolean updateBytesTransferred(long bytesTransferred) {

    }

    @Override
    public List<Session> findActiveSessions() {

    }

    @Override
    public List<Session> findUserSessions(String userId) {

    }
}
