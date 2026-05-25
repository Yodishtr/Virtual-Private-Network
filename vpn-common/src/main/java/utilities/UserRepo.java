package utilities;

import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface UserRepo {

    Optional<User> findByUsername(String username) throws SQLException;

    User createUser(String username, String passwordHash, User.Role role, User.Status status, int maxConnections);

    boolean updateLastLogin(String username, Instant timestamp);

    boolean updateUserStatus(String username, User.Status newStatus);

    List<User> findAllUsers();

    int countActiveSessionsForUser(String username);


}
