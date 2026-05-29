package db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

public class DatabaseManager {

    private static final HikariDataSource hikariDataSource;

    static {
        HikariConfig hikariConfig = new HikariConfig();
        Properties serverProperties = new Properties();
        InputStream serverPropertiesStream = DatabaseManager.class.getClassLoader().
                getResourceAsStream("server.properties");
        if (serverPropertiesStream == null) {
            throw new RuntimeException("Unable to find server properties file");
        }
        try {
            serverProperties.load(serverPropertiesStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        hikariConfig.setJdbcUrl(serverProperties.getProperty("db.url"));
        hikariConfig.setUsername(serverProperties.getProperty("db.username"));
        hikariConfig.setPassword(serverProperties.getProperty("db.password"));
        hikariConfig.setMaximumPoolSize(Integer.parseInt(serverProperties.getProperty("db.pool.size")));
        hikariConfig.setConnectionTimeout(Integer.parseInt(serverProperties.getProperty("db.connection.timeout")));
        hikariConfig.setIdleTimeout(Integer.parseInt(serverProperties.getProperty("db.connection.idle.timeout")));
        hikariConfig.setMaxLifetime(Integer.parseInt(serverProperties.getProperty("db.connection.maxlifetime")));
        hikariDataSource = new HikariDataSource(hikariConfig);
    }

    public static DataSource getConnection() throws SQLException {
        return hikariDataSource;
    }
}
