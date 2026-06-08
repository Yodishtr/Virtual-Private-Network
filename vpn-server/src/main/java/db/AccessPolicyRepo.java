package db;

import utilities.AccessPolicy;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

public interface AccessPolicyRepo {

    Optional<AccessPolicy> getAccessPolicyByUsername(String username);

    Optional<AccessPolicy> createAccessPolicy(String username, Integer allowedFromHour, Integer allowedToHour,
                                              List<String> ipAllowList, Integer bandwidthLimit);

    Integer updateAccessPolicy(String username, Integer allowedFromHour, Integer allowedToHour,
                               List<String> ipAllowList, Integer bandwidthLimit);
}
