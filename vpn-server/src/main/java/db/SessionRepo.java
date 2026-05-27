package db;

public interface SessionRepo {

    long createNewSession();

    boolean updateDisconnectSessionTimeAndReason(String reason);
}
