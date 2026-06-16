package db;

import utilities.AccessPolicy;

import javax.sql.DataSource;
import java.sql.*;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class AccessPolicyRepository implements AccessPolicyRepo{
    private final DataSource dataSource;

    public AccessPolicyRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public Optional<AccessPolicy> getAccessPolicyByUsername(String username) {
        String sqlStatement = "SELECT * FROM access_policy WHERE user_id = ?";
        try (Connection connection = dataSource.getConnection();
        PreparedStatement preparedStatement = connection.prepareStatement(sqlStatement)) {
            preparedStatement.setString(1, username);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    long accessPolicyId = resultSet.getLong("id");
                    String userName = resultSet.getString("user_id");
                    Integer allowedFromHour = resultSet.getInt("allowed_from_hour");
                    Integer allowedToHour = resultSet.getInt("allowed_to_hour");
                    Array inetArray = resultSet.getArray("ip_allowlist");
                    List<String> ipAllowList = new ArrayList<>();
                    if (inetArray != null) {
                        String[] currStringArray = (String[]) inetArray.getArray();
                        ipAllowList = Arrays.asList(currStringArray);
                    }
                    Integer bandwidthLimit = resultSet.getInt("bandwidth_limit");
                    OffsetDateTime createdAt = resultSet.getObject("created_at", OffsetDateTime.class);
                    OffsetDateTime updatedAt = resultSet.getObject("updated_at", OffsetDateTime.class);
                    AccessPolicy currAccessPolicy = new AccessPolicy(accessPolicyId, userName, allowedFromHour,
                            allowedToHour, ipAllowList, bandwidthLimit, createdAt, updatedAt);
                    return Optional.of(currAccessPolicy);
                } else {
                    return Optional.empty();
                }
            }

        } catch (SQLException e){
            e.printStackTrace();
        }
        return Optional.empty();
    }

    @Override
    public Optional<AccessPolicy> createAccessPolicy(String username, Integer allowedFromHour, Integer allowedToHour,
                                                     List<String> ipAllowList, Integer bandwidthLimit) {
        if (username == null || username.isEmpty() ) {
            return Optional.empty();
        }
        String insertSqlStatment = "INSERT INTO access_policies (user_id, allowed_from_hour, allowed_to_hour, " +
                "ip_allowlist, bandwidth_limit_mbps) VALUES (?, ?, ?, ?, ?) RETURNING *";
        try (Connection connection = this.dataSource.getConnection();
        PreparedStatement preparedStatement = connection.prepareStatement(insertSqlStatment)) {
            preparedStatement.setString(1, username);
            preparedStatement.setInt(2, allowedFromHour);
            preparedStatement.setInt(3, allowedToHour);

            String[] ipStringArray = ipAllowList.toArray(new String[ipAllowList.size()]);
            Array sqlArray = connection.createArrayOf("inet", ipStringArray);
            preparedStatement.setArray(4, sqlArray);
            preparedStatement.setInt(5, bandwidthLimit);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    long accessPolicyId = resultSet.getLong("id");
                    String userName = resultSet.getObject("user_id").toString();
                    Integer allowedFromHourInt = resultSet.getInt("allowed_from_hour");
                    Integer allowedToHourInt = resultSet.getInt("allowed_to_hour");
                    Array inetArray = resultSet.getArray("ip_allowlist");
                    List<String> ipAllowListRetrieved = new ArrayList<>();
                    if (inetArray != null) {
                        String[] currStringArray = (String[]) inetArray.getArray();
                        ipAllowListRetrieved = Arrays.asList(currStringArray);
                    }
                    Integer bandwidthLimitInt = resultSet.getInt("bandwidth_limit_mbps");
                    OffsetDateTime createdAtInt = resultSet.getObject("created_at", OffsetDateTime.class);
                    OffsetDateTime updatedAt = resultSet.getObject("updated_at", OffsetDateTime.class);
                    AccessPolicy accessPolicyCreated = new AccessPolicy(accessPolicyId, userName, allowedFromHour,
                            allowedToHour, ipAllowListRetrieved, bandwidthLimitInt, createdAtInt, updatedAt);
                    return Optional.of(accessPolicyCreated);
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
    public Integer updateAccessPolicy(String username, Integer allowedFromHour, Integer allowedToHour,
                                      List<String> ipAllowList, Integer bandwidthLimit) {}
}
