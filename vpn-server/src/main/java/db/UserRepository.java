package db;

import utilities.User;
import utilities.UserRepo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public class UserRepository implements UserRepo {

    private final Connection connection;

    public UserRepository(Connection connection) {
        this.connection = connection;
    }

    @Override
    public Optional<User> findByUsername(String username) throws SQLException {
        String sqlStatement = "SELECT * FROM users WHERE username = ?";
        PreparedStatement preparedStatement = this.connection.prepareStatement(sqlStatement);

    }

    @Override
    public User createUser(String username, String passwordHash, User.Role role, User.Status status,
                           int maxConnections) {

    }

    @Override
    public boolean updateLastLogin(String username, Instant timestamp) {

    }

    @Override
    public boolean updateUserStatus(String username, User.Status status) {

    }

    @Override
    public List<User> findAllUsers() {

    }

    @Override
    public int countActiveSessionsForUser(String username) {

    }
}
