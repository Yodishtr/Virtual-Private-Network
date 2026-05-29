package db;

import utilities.Session;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class SessionRepository implements SessionRepo {

    private final DataSource dataSource;

    public SessionRepository(DataSource dataSource) {
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
    public Optional<Session> updateBytesTransferred(long byteSent, long byteReceived, long sessionId) {
        String retrieveSqlStatement = "SELECT * FROM sessions WHERE id = ?";
        String updateSqlStatement = "UPDATE sessions SET bytes_sent = ?, bytes_received = ? WHERE id = ? RETURNING *";
        try (Connection connection = this.dataSource.getConnection();
        PreparedStatement retrievePreparedStatement = connection.prepareStatement(retrieveSqlStatement);
        PreparedStatement updatePreparedStatement = connection.prepareStatement(updateSqlStatement)) {
            retrievePreparedStatement.setLong(1, sessionId);
            ResultSet retrieveResultSet = retrievePreparedStatement.executeQuery();
            if (retrieveResultSet.next()) {
                long currentBytesSent = retrieveResultSet.getLong("bytes_sent") + byteSent;
                long currentBytesReceived = retrieveResultSet.getLong("bytes_received") + byteReceived;
                updatePreparedStatement.setLong(1, currentBytesSent);
                updatePreparedStatement.setLong(2, currentBytesReceived);
                updatePreparedStatement.setLong(3, sessionId);
                ResultSet updateResultSet = updatePreparedStatement.executeQuery();
                if (updateResultSet.next()) {
                    long userID = updateResultSet.getLong("user_id");
                    String clientIp = updateResultSet.getObject("client_ip").toString();
                    OffsetDateTime connectedAt = updateResultSet.getObject("connected_at", OffsetDateTime.class);
                    OffsetDateTime disconnectAt = updateResultSet.getObject("disconnect_at", OffsetDateTime.class);
                    long bytesSent = updateResultSet.getLong("bytes_sent");
                    long bytesReceived = updateResultSet.getLong("bytes_received");
                    String disconnectReason = updateResultSet.getString("disconnect_reason");
                    UUID sessionToken = updateResultSet.getObject("session_token", UUID.class);
                    Session currentSessionUpdated = new Session(sessionId, userID, clientIp, connectedAt, disconnectAt,
                            bytesSent, bytesReceived, disconnectReason, sessionToken);
                    return Optional.of(currentSessionUpdated);
                }
            } else {
                throw new RuntimeException("no session with that id has been found");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (RuntimeException e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }

    @Override
    public List<Session> findActiveSessions() {
        List<Session> resultList = new ArrayList<>();
        String selectSqlStatement = "SELECT * FROM sessions WHERE disconnected_at IS NULL";
        try (Connection connection = this.dataSource.getConnection();
        PreparedStatement selectPreparedStatement = connection.prepareStatement(selectSqlStatement);
        ResultSet resultSet = selectPreparedStatement.executeQuery()) {
            while (resultSet.next()) {
                long sessionId = resultSet.getLong("id");
                long userID = resultSet.getLong("user_id");
                String clientIp = resultSet.getObject("client_ip").toString();
                OffsetDateTime connectedAt = resultSet.getObject("connected_at", OffsetDateTime.class);
                long bytesSent = resultSet.getLong("bytes_sent");
                long bytesReceived = resultSet.getLong("bytes_received");
                UUID sessionToken = resultSet.getObject("session_token", UUID.class);
                Session currentActiveSession = new Session(sessionId, userID, clientIp, connectedAt, null,
                        bytesSent, bytesReceived, null, sessionToken);
                resultList.add(currentActiveSession);
            }
            return resultList;
        } catch (SQLException e) {
            e.printStackTrace();
            return resultList;
        }
    }

    @Override
    public int countActiveSessions() {
        String countSqlStatement = "SELECT COUNT(*) FROM sessions WHERE disconnected_at IS NULL";
        try (Connection connection = this.dataSource.getConnection();
        PreparedStatement countPreparedStatement = connection.prepareStatement(countSqlStatement);
        ResultSet resultSet = countPreparedStatement.executeQuery()) {
            if (resultSet.next()) {
                return resultSet.getInt(1);
            }
            return 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return -1;
        }
    }

    @Override
    public List<Session> findUserSessions(String username) {
        List<Session> resultList = new ArrayList<>();
        String findUserIdSqlStatement = "SELECT * FROM users WHERE username = ?";
        String findSessionSqlStatement = "SELECT * FROM sessions WHERE user_id = ?";
        try (Connection connection  = this.dataSource.getConnection();
        PreparedStatement findSessionPreparedStatement = connection.prepareStatement(findSessionSqlStatement);
        PreparedStatement findUserPreparedStatement = connection.prepareStatement(findUserIdSqlStatement)) {

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
