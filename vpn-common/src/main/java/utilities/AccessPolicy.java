package utilities;

import java.time.OffsetDateTime;
import java.util.List;

public class AccessPolicy {

    private long id;
    private String userId;
    private Integer allowedFromHour;
    private Integer allowedToHour;
    private List<String> ipAllowList;
    private Integer bandwidthLimit;
    private OffsetDateTime createdAt;
    private OffsetDateTime updatedAt;

    public AccessPolicy(long id, String userId, Integer allowedFromHour, Integer allowedToHour, List<String> ipAllowList,
                        Integer bandwidthLimit, OffsetDateTime createdAt, OffsetDateTime updatedAt) {
        this.id = id;
        this.userId = userId;
        this.allowedFromHour = allowedFromHour;
        this.allowedToHour = allowedToHour;
        this.ipAllowList = ipAllowList;
        this.bandwidthLimit = bandwidthLimit;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public AccessPolicy() {}

    // Getters
    public long getId() {
        return id;
    }

    public String getUserId() {
        return userId;
    }

    public Integer getAllowedFromHour() {
        return allowedFromHour;
    }

    public Integer getAllowedToHour() {
        return allowedToHour;
    }

    public List<String> getIpAllowList() {
        return ipAllowList;
    }

    public Integer getBandwidthLimit() {
        return bandwidthLimit;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }

    // Setters
    public void setId(long id) {
        this.id = id;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setAllowedFromHour(Integer allowedFromHour) {
        this.allowedFromHour = allowedFromHour;
    }

    public void setAllowedToHour(Integer allowedToHour) {
        this.allowedToHour = allowedToHour;
    }

    public void setIpAllowList(List<String> ipAllowList) {
        this.ipAllowList = ipAllowList;
    }

    public void setBandwidthLimit(Integer bandwidthLimit) {
        this.bandwidthLimit = bandwidthLimit;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public void setUpdatedAt(OffsetDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
