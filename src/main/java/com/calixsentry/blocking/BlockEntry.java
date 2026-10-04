package com.calixsentry.blocking;

import java.time.Instant;

public class BlockEntry {
    private String ip;
    private String reason;
    private String ruleId;
    private BlockType type;
    private String createdBy; // "SYSTEM" for automatic blocks, admin username for manual
    private Instant createdAt;
    private Instant expiresAt; // null for PERMANENT

    public BlockEntry() { }

    public BlockEntry(String ip, String reason, String ruleId, BlockType type,
                       String createdBy, Instant createdAt, Instant expiresAt) {
        this.ip = ip;
        this.reason = reason;
        this.ruleId = ruleId;
        this.type = type;
        this.createdBy = createdBy;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public boolean isExpired() {
        return type == BlockType.TEMPORARY && expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }
    public BlockType getType() { return type; }
    public void setType(BlockType type) { this.type = type; }
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
}
