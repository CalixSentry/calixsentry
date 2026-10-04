package com.calixsentry.api;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.Detector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * {basePath}/api/detection - lets an administrator enable/disable an
 * individual detection RULE at runtime (spec section 6: every rule has an
 * "Enabled/disabled state"), without a restart. Maps a rule's category to
 * the matching CalixSentryProperties.Detection flag that its isEnabled()
 * actually reads, so the toggle is real - not a UI switch with nothing
 * behind it.
 */
@RestController
@RequestMapping("${calixsentry.management.base-path}/api/detection")
public class DetectionToggleController {

    private static final Logger log = LoggerFactory.getLogger(DetectionToggleController.class);

    private final CalixSentryProperties properties;
    private final List<Detector> detectors;

    public DetectionToggleController(CalixSentryProperties properties, List<Detector> detectors) {
        this.properties = properties;
        this.detectors = detectors;
    }

    public record ToggleRequest(String ruleId, boolean enabled) {}

    private Consumer<Boolean> setterFor(String ruleId) {
        var d = properties.getDetection();
        return switch (ruleId) {
            case "CS-SQLI-001" -> d::setSqlInjection;
            case "CS-XSS-001" -> d::setXss;
            case "CS-TRAVERSAL-001" -> d::setPathTraversal;
            case "CS-CMDI-001" -> d::setCommandInjection;
            case "CS-SENSITIVE-001" -> d::setSensitivePaths;
            case "CS-BOT-UA-001" -> d::setScannerUserAgents;
            case "CS-BOT-001" -> d::setEndpointEnumeration;
            case "CS-RATE-001" -> d::setBotScanning;
            default -> null;
        };
    }

    @PutMapping("/{ruleId}")
    public ResponseEntity<?> toggle(@PathVariable String ruleId, @RequestBody Map<String, Boolean> body,
                                     @AuthenticationPrincipal UserDetails user) {
        Boolean enabled = body.get("enabled");
        if (enabled == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Body must include {\"enabled\": true|false}"));
        }
        Consumer<Boolean> setter = setterFor(ruleId);
        if (setter == null) {
            return ResponseEntity.notFound().build();
        }
        String actor = user != null ? user.getUsername() : "unknown";
        log.warn("Rule {} {} (by {})", ruleId, enabled ? "ENABLED" : "DISABLED", actor);
        setter.accept(enabled);

        return detectors.stream()
                .filter(d -> d.ruleId().equals(ruleId))
                .findFirst()
                .<ResponseEntity<?>>map(d -> ResponseEntity.ok(Map.of("ruleId", ruleId, "enabled", d.isEnabled())))
                .orElseGet(() -> ResponseEntity.ok(Map.of("ruleId", ruleId, "enabled", enabled)));
    }
}
