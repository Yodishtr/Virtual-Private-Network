package utilities;

import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface UserRepo {

    Optional<User> findByUsername(String username) throws SQLException;

    User createUser(String username, String passwordHash, String role, String status, int maxConnections) throws SQLException;

    boolean updateLastLogin(String username) throws SQLException;

    boolean updateUserStatus(String username, String newStatus) throws SQLException;

    List<User> findAllUsers() throws SQLException;

}
