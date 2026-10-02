package com.calixsentry.activity;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.logs.DailyLogService;
import com.calixsentry.logs.LogKind;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Called once for EVERY request the gateway handles. Feeds the live per-IP view and,
 * if enabled, appends the request to today's access log file. Never throws - a logging
 * problem must never break request handling.
 */
@Component
public class AccessRecorder {

    private static final Logger log = LoggerFactory.getLogger(AccessRecorder.class);

    private final IpActivityStore ipStore;
    private final DailyLogService dailyLogs;
    private final CalixSentryProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();

    public AccessRecorder(IpActivityStore ipStore, DailyLogService dailyLogs, CalixSentryProperties properties) {
        this.ipStore = ipStore;
        this.dailyLogs = dailyLogs;
        this.properties = properties;
    }

    public void record(String ip, String method, String uri, String path, String userAgent,
                       Integer status, String action, int score, String category, String ruleId) {
        try {
            ipStore.record(ip, method, uri, path, status, action, score);

            if (!properties.getEvents().isAccessLogEnabled()) return;

            ObjectNode node = mapper.createObjectNode();
            node.put("timestamp", Instant.now().toString());
            node.put("sourceIp", ip);
            node.put("method", method);
            node.put("uri", clip(uri, 500));
            if (status != null) node.put("status", status.intValue());
            node.put("action", action);
            node.put("threatScore", score);
            if (category != null) node.put("category", category);
            if (ruleId != null) node.put("ruleId", ruleId);
            if (userAgent != null) node.put("userAgent", clip(userAgent, 200));
            dailyLogs.append(LogKind.ACCESS, mapper.writeValueAsString(node));
        } catch (Exception e) {
            log.warn("Access recording failed: {}", e.getMessage());
        }
    }

    private static String clip(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }
}
