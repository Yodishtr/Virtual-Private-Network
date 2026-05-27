package db;

import utilities.User;

import java.util.List;
import java.util.Optional;

public interface UserRepo {

    Optional<User> findByUsername(String username);

    User createUser(String username, String passwordHash, String role, String status, int maxConnections);

    boolean updateLastLogin(String username);

    boolean updateUserStatus(String username, String newStatus);

    List<User> findAllUsers();

}
