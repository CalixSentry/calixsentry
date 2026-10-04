package com.calixsentry.events;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Structured security-event record, matching the shape described in spec
 * section 11. Every field the "Why was this detected?" dashboard view needs
 * lives here: classification, score, evidence (reasons), the recommended
 * action vs. the action actually taken, and the rule that fired.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SecurityEvent {

    private String id;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private Instant timestamp;
    private String sourceIp;
    private String method;
    private String uri;
    private String userAgent;
    private Integer status;         // backend response status; null if blocked before forwarding
    private String category;
    private String severity;
    private int threatScore;
    private String action;              // action actually applied
    private String recommendedAction;   // what policy would recommend (relevant in MONITOR/ALERT/MANUAL)
    private String ruleId;
    private List<String> reasons;
    private Long blockDurationSeconds;  // populated when a temporary block resulted

    public static SecurityEvent.Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final SecurityEvent event = new SecurityEvent();
        Builder() {
            event.id = UUID.randomUUID().toString();
            event.timestamp = Instant.now();
        }
        public Builder sourceIp(String v) { event.sourceIp = v; return this; }
        public Builder method(String v) { event.method = v; return this; }
        public Builder uri(String v) { event.uri = v; return this; }
        public Builder userAgent(String v) { event.userAgent = v; return this; }
        public Builder status(Integer v) { event.status = v; return this; }
        public Builder category(String v) { event.category = v; return this; }
        public Builder severity(String v) { event.severity = v; return this; }
        public Builder threatScore(int v) { event.threatScore = v; return this; }
        public Builder action(String v) { event.action = v; return this; }
        public Builder recommendedAction(String v) { event.recommendedAction = v; return this; }
        public Builder ruleId(String v) { event.ruleId = v; return this; }
        public Builder reasons(List<String> v) { event.reasons = v; return this; }
        public Builder blockDurationSeconds(Long v) { event.blockDurationSeconds = v; return this; }
        public SecurityEvent build() { return event; }
    }

    public String getId() { return id; }
    public Instant getTimestamp() { return timestamp; }
    public String getSourceIp() { return sourceIp; }
    public String getMethod() { return method; }
    public String getUri() { return uri; }
    public String getUserAgent() { return userAgent; }
    public Integer getStatus() { return status; }
    public void setStatus(Integer status) { this.status = status; }
    public String getCategory() { return category; }
    public String getSeverity() { return severity; }
    public int getThreatScore() { return threatScore; }
    public String getAction() { return action; }
    public String getRecommendedAction() { return recommendedAction; }
    public String getRuleId() { return ruleId; }
    public List<String> getReasons() { return reasons; }
    public Long getBlockDurationSeconds() { return blockDurationSeconds; }
}
