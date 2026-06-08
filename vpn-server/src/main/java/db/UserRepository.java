package db;

import com.zaxxer.hikari.HikariDataSource;
import utilities.User;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class UserRepository implements UserRepo {

    private final DataSource dataSource;

    public UserRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public Optional<User> findByUsername(String username) {
        String sqlStatement = "SELECT * FROM users WHERE username = ?";
        // the method structure should be as follows:
        // borrows a fresh connection from the connection pool
        try (Connection connection = this.dataSource.getConnection();
             // do the prepared statement within the try-with
        PreparedStatement preparedStatement = connection.prepareStatement(sqlStatement)) {
            preparedStatement.setString(1, username);
            // execute your query and get your results
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    long user_id = resultSet.getLong("id");
                    String passwordHash = resultSet.getString("password_hash");
                    String userRole = resultSet.getString("role");
                    String userStatus = resultSet.getString("status");
                    Instant createdAt = resultSet.getTimestamp("created_at").toInstant();
                    Instant lastLogin = null;
                    if (resultSet.getTimestamp("last_login") != null) {
                        lastLogin = resultSet.getTimestamp("last_login").toInstant();
                    }
                    int maxConnections = resultSet.getInt("max_connections");
                    User foundUser = new User(username, passwordHash, User.Role.fromString(userRole),
                            User.Status.fromString(userStatus), createdAt, lastLogin, user_id, maxConnections);
                    return Optional.of(foundUser);
                } else {
                    return Optional.empty();
                }
            }
            // result set is closed and thus prevents resource leaks.
        } catch (SQLException e) {
            e.printStackTrace();

        }
        // prepared statement and connection automatically closed here safely while catch clause handles db errors
        // and with the try-with block hikariCP takes the connection back to the connection pool
        return Optional.empty();
    }

    @Override
    public User createUser(String username, String passwordHash, String role, String status,
                           int maxConnections) {
        if (username == null || passwordHash == null || role == null || status == null || maxConnections <= 0) {
            return null;
        }
        String insertStatement = "INSERT INTO users (username, password_hash, role, status, max_connections) " +
                "VALUES (?, ?, ?, ?, ?)";
        try (Connection currentConnection = this.dataSource.getConnection();
        PreparedStatement preparedStatement = currentConnection.prepareStatement(insertStatement)) {
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, passwordHash);
            preparedStatement.setString(3, role);
            preparedStatement.setString(4, status);
            preparedStatement.setInt(5, maxConnections);
            int result = preparedStatement.executeUpdate();
            if (result == 1) {
                return new User(username, passwordHash, User.Role.fromString(role), User.Status.fromString(status),
                        maxConnections);
            } else {
                return null;
            }
        } catch (SQLException e) {
            e.printStackTrace();

        }
        return null;
    }

    @Override
    public boolean updateLastLogin(String username) {
        if (username == null) {
            return false;
        }
        String updateSqlStatement = " UPDATE users SET last_login = NOW() WHERE username = ?";
        try (Connection connection = this.dataSource.getConnection();
        PreparedStatement preparedStatement = connection.prepareStatement(updateSqlStatement)) {
            preparedStatement.setString(1, username);
            int result = preparedStatement.executeUpdate();
            return result == 1;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean updateUserStatus(String username, String status) {
        if (username == null || status == null) {
            return false;
        }
        String updateStatement = "UPDATE users SET status = ? WHERE username = ?";
        try (Connection connection = this.dataSource.getConnection();
        PreparedStatement preparedStatement = connection.prepareStatement(updateStatement)) {
            preparedStatement.setString(1, status);
            preparedStatement.setString(2, username);
            int result = preparedStatement.executeUpdate();
            return result == 1;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public List<User> findAllUsers() {
        List<User> resultsList = new ArrayList<>();
        String retrieveSqlStatement = "SELECT * FROM users";
        try (Connection connection = this.dataSource.getConnection();
        PreparedStatement preparedStatement = connection.prepareStatement(retrieveSqlStatement);
             ResultSet resultSet = preparedStatement.executeQuery()) {
            while (resultSet.next()) {
                long user_id = resultSet.getLong("id");
                String username = resultSet.getString("username");
                String passwordHash = resultSet.getString("password_hash");
                String role = resultSet.getString("role");
                String status = resultSet.getString("status");
                Instant createdAt = resultSet.getTimestamp("created_at").toInstant();
                Instant lastLogin = null;
                if (resultSet.getTimestamp("last_login") != null) {
                    lastLogin = resultSet.getTimestamp("last_login").toInstant();
                }
                int maxConnections = resultSet.getInt("max_connections");
                User foundUser = new User(username, passwordHash, User.Role.fromString(role),
                        User.Status.fromString(status), createdAt, lastLogin, user_id, maxConnections);
                resultsList.add(foundUser);
            }
        } catch(SQLException e) {
            e.printStackTrace();
        }
        return resultsList;
    }
}
