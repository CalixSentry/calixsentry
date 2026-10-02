package com.calixsentry.api;

import com.calixsentry.blocking.BlockStore;
import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.Detector;
import com.calixsentry.events.SecurityEvent;
import com.calixsentry.events.SecurityEventPublisher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * GET {basePath}/api/status and /api/stats - the numbers behind the
 * dashboard header and CLI `calixsentry status` (spec sections 12, 20).
 */
@RestController
@RequestMapping("${calixsentry.management.base-path}/api")
public class StatusController {

    private final CalixSentryProperties properties;
    private final List<Detector> detectors;
    private final BlockStore blockStore;
    private final SecurityEventPublisher eventPublisher;

    public StatusController(CalixSentryProperties properties, List<Detector> detectors,
                             BlockStore blockStore, SecurityEventPublisher eventPublisher) {
        this.properties = properties;
        this.detectors = detectors;
        this.blockStore = blockStore;
        this.eventPublisher = eventPublisher;
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("product", "CalixSentry");
        result.put("version", "0.1.0-MVP");
        result.put("protectionMode", properties.getProtection().getMode());
        result.put("automaticBlocking", properties.getProtection().isAutomaticBlocking());
        result.put("rulesLoaded", detectors.size());
        result.put("activeBlocks", blockStore.listActiveBlocks().size());
        return result;
    }

    @GetMapping("/rules")
    public List<Map<String, Object>> rules() {
        return detectors.stream().map(d -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ruleId", d.ruleId());
            m.put("name", d.name());
            m.put("category", d.category());
            m.put("severity", d.severity());
            m.put("description", d.description());
            m.put("enabled", d.isEnabled());
            return m;
        }).collect(Collectors.toList());
    }

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        List<SecurityEvent> recent = eventPublisher.recentEvents(2000);

        Map<String, Long> byCategory = recent.stream()
                .collect(Collectors.groupingBy(SecurityEvent::getCategory, Collectors.counting()));
        Map<String, Long> byIp = recent.stream()
                .collect(Collectors.groupingBy(SecurityEvent::getSourceIp, Collectors.counting()));
        Map<String, Long> byUri = recent.stream()
                .collect(Collectors.groupingBy(SecurityEvent::getUri, Collectors.counting()));

        long notFoundCount = recent.stream().filter(e -> e.getStatus() != null && e.getStatus() == 404).count();
        long blocked = recent.stream().filter(e -> "BLOCK".equals(e.getAction()) || "TEMPORARY_BLOCK".equals(e.getAction())).count();
        long rateLimited = recent.stream().filter(e -> "RATE_LIMIT".equals(e.getAction())).count();
        long alerts = recent.stream().filter(e -> "ALERT".equals(e.getAction())).count();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("securityEventsRetained", recent.size());
        result.put("blockedRequests", blocked);
        result.put("rateLimitedRequests", rateLimited);
        result.put("alerts", alerts);
        result.put("activeBlocks", blockStore.listActiveBlocks().size());
        result.put("notFoundInRetainedEvents", notFoundCount);
        result.put("topAttackTypes", topN(byCategory, 10));
        result.put("topSuspiciousIps", topN(byIp, 10));
        result.put("topScannedUrls", topN(byUri, 10));
        return result;
    }

    private List<Map.Entry<String, Long>> topN(Map<String, Long> map, int n) {
        return map.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .limit(n)
                .collect(Collectors.toList());
    }
}
