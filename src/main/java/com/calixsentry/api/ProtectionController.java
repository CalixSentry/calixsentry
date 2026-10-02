package com.calixsentry.api;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.policy.ProtectionMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {basePath}/api/protection - the dashboard's "engine on/off" control.
 *
 * There is deliberately no literal "turn the WAF completely off" switch here
 * (bypassing detection entirely would be a much larger, easier-to-misuse
 * foot-gun, and nothing in the product spec asks for it). What this DOES
 * expose, live, without a restart, is exactly the two things spec section 3
 * and 18 talk about: the Protection Mode (MONITOR/ALERT/MANUAL/AUTOMATIC) and
 * the automatic-blocking master switch. Because PolicyEngine reads
 * CalixSentryProperties fresh on every request rather than caching them, a
 * change made here takes effect on the very next request.
 *
 * Every change is logged with the acting admin's username - this is a
 * meaningful security-relevant action, not a cosmetic setting.
 */
@RestController
@RequestMapping("${calixsentry.management.base-path}/api/protection")
public class ProtectionController {

    private static final Logger log = LoggerFactory.getLogger(ProtectionController.class);

    private final CalixSentryProperties properties;

    public ProtectionController(CalixSentryProperties properties) {
        this.properties = properties;
    }

    public record ProtectionUpdateRequest(String mode, Boolean automaticBlocking) {}

    @GetMapping
    public Map<String, Object> get() {
        return snapshot();
    }

    @PutMapping
    public ResponseEntity<?> update(@RequestBody ProtectionUpdateRequest request,
                                     @AuthenticationPrincipal UserDetails user) {
        String actor = user != null ? user.getUsername() : "unknown";

        if (request.mode() != null) {
            ProtectionMode parsed;
            try {
                parsed = ProtectionMode.valueOf(request.mode().trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Invalid mode. Must be one of MONITOR, ALERT, MANUAL, AUTOMATIC."));
            }
            log.warn("Protection mode changed: {} -> {} (by {})", properties.getProtection().getMode(), parsed, actor);
            properties.getProtection().setMode(parsed.name());
        }

        if (request.automaticBlocking() != null) {
            log.warn("Automatic blocking changed: {} -> {} (by {})",
                    properties.getProtection().isAutomaticBlocking(), request.automaticBlocking(), actor);
            properties.getProtection().setAutomaticBlocking(request.automaticBlocking());
        }

        return ResponseEntity.ok(snapshot());
    }

    private Map<String, Object> snapshot() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("mode", properties.getProtection().getMode());
        result.put("automaticBlocking", properties.getProtection().isAutomaticBlocking());
        result.put("alertThreshold", properties.getProtection().getAlertThreshold());
        result.put("automaticBlockThreshold", properties.getProtection().getAutomaticBlockThreshold());
        return result;
    }
}
