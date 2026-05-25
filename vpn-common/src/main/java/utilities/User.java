package utilities;

import java.time.Instant;
import java.time.LocalDateTime;

public class User {

    public enum Role {
        USER("User"),
        ADMIN("Admin");

        private final String currRole;

        private Role(String role) {
            this.currRole = role;
        }

        public String getCurrRole() {
            return currRole;
        }

        public static Role fromString(String role) {
            for (Role r : Role.values()) {
                if (r.getCurrRole().equals(role)) {
                    return r;
                }
            }
            return null;
        }
    }


    public enum Status {
        ACTIVE("active"),
        SUSPENDED("suspended"),
        DELETED("deleted");

        private final String currStatus;

        private Status(String status) {
            this.currStatus = status;
        }

        public String getCurrStatus() {
            return currStatus;
        }

        public static Status fromString(String status) {
            for (Status s : Status.values()) {
                if (s.getCurrStatus().equals(status)) {
                    return s;
                }
            }
            return null;
        }
    }

    private long id;
    private String username;
    private String passwordHash;
    private String role;
    private String status;
    private Instant createdAt;
    private Instant lastLogin;
    private Integer maxConnections;

    public User(String username, String passwordHash, String role, String status, Instant createdAt,
                Instant lastLogin, long id, Integer maxConnections) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.status = status;
        this.createdAt = createdAt;
        this.lastLogin = lastLogin;
        this.maxConnections = maxConnections;
    }

    // Getters
    public long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getRole() {
        return role;
    }

    public String getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getLastLogin() {
        return lastLogin;
    }

    public Integer getMaxConnections() {
        return maxConnections;
    }

    // Setters
    public void setId(long id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public void setLastLogin(Instant lastLogin) {
        this.lastLogin = lastLogin;
    }

    public void setMaxConnections(Integer maxConnections) {
        this.maxConnections = maxConnections;
    }
}
