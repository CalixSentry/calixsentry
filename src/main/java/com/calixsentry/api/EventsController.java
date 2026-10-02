package com.calixsentry.api;

import com.calixsentry.events.SecurityEvent;
import com.calixsentry.events.SecurityEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Locale;

/**
 * {basePath}/api/events - "LIVE SECURITY EVENTS" feed + event detail (spec
 * sections 12, 13), with real server-side filtering so the dashboard's search
 * box and filter dropdowns operate over the full retained event history, not
 * just whatever page happened to be fetched.
 */
@RestController
@RequestMapping("${calixsentry.management.base-path}/api/events")
public class EventsController {

    private final SecurityEventPublisher eventPublisher;

    public EventsController(SecurityEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @GetMapping
    public List<SecurityEvent> recent(
            @RequestParam(defaultValue = "100") int limit,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String q) {

        List<SecurityEvent> all = eventPublisher.recentEvents(eventPublisher.totalRetained());

        String qLower = q == null ? null : q.toLowerCase(Locale.ROOT);

        return all.stream()
                .filter(e -> ip == null || ip.isBlank() || e.getSourceIp().equalsIgnoreCase(ip))
                .filter(e -> category == null || category.isBlank() || category.equalsIgnoreCase(e.getCategory()))
                .filter(e -> severity == null || severity.isBlank() || severity.equalsIgnoreCase(e.getSeverity()))
                .filter(e -> action == null || action.isBlank() || action.equalsIgnoreCase(e.getAction()))
                .filter(e -> qLower == null || qLower.isBlank()
                        || (e.getUri() != null && e.getUri().toLowerCase(Locale.ROOT).contains(qLower))
                        || (e.getSourceIp() != null && e.getSourceIp().toLowerCase(Locale.ROOT).contains(qLower))
                        || (e.getUserAgent() != null && e.getUserAgent().toLowerCase(Locale.ROOT).contains(qLower))
                        || (e.getReasons() != null && e.getReasons().stream().anyMatch(r -> r.toLowerCase(Locale.ROOT).contains(qLower))))
                .limit(Math.min(limit, 2000))
                .toList();
    }

    @GetMapping("/{id}")
    public ResponseEntity<SecurityEvent> byId(@PathVariable String id) {
        return eventPublisher.findById(id).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }
}
