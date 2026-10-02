package com.calixsentry.accesslist;

import java.time.Instant;

/**
 * A single allowlist/denylist entry. Supports IP or CIDR per spec section 15.
 * User-Agent/Country/ASN/header-based conditions are FUTURE FEATURE - not
 * implemented in this MVP (see docs/ROADMAP.md) - the `type` field exists
 * now so the API/model won't need a breaking change later.
 */
public class AccessListEntry {
    public enum ListType { ALLOW, DENY }
    public enum MatchType { IP, CIDR }

    private String value;     // e.g. "10.0.0.5" or "10.0.0.0/24"
    private ListType listType;
    private MatchType matchType;
    private String reason;
    private String createdBy;
    private Instant createdAt;

    public AccessListEntry() { }

    public AccessListEntry(String value, ListType listType, MatchType matchType, String reason,
                            String createdBy, Instant createdAt) {
        this.value = value;
        this.listType = listType;
        this.matchType = matchType;
        this.reason = reason;
        this.createdBy = createdBy;
        this.createdAt = createdAt;
    }

    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
    public ListType getListType() { return listType; }
    public void setListType(ListType listType) { this.listType = listType; }
    public MatchType getMatchType() { return matchType; }
    public void setMatchType(MatchType matchType) { this.matchType = matchType; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
