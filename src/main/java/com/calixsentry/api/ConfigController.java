package com.calixsentry.api;

import com.calixsentry.config.CalixSentryProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {basePath}/api/config - read-only view of the EFFECTIVE configuration.
 * No secrets live in this object (passwords are never part of
 * CalixSentryProperties), so this is safe to expose to ANALYST/VIEWER roles.
 */
@RestController
@RequestMapping("${calixsentry.management.base-path}/api/config")
public class ConfigController {

    private final CalixSentryProperties properties;

    public ConfigController(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @GetMapping
    public Map<String, Object> effectiveConfig() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("protectionMode", properties.getProtection().getMode());
        result.put("automaticBlocking", properties.getProtection().isAutomaticBlocking());
        result.put("alertThreshold", properties.getProtection().getAlertThreshold());
        result.put("automaticBlockThreshold", properties.getProtection().getAutomaticBlockThreshold());
        result.put("automaticBlockDuration", properties.getProtection().getAutomaticBlockDuration().toString());
        result.put("detection", properties.getDetection());
        result.put("scoring", properties.getScoring());
        result.put("rateLimit", properties.getRateLimit());
        result.put("elasticsearchEnabled", properties.getElasticsearch().isEnabled());
        return result;
    }
}
