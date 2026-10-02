package com.calixsentry.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Plain, unauthenticated /health endpoint (spec section 28), separate from /actuator/health. */
@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP", "product", "CalixSentry");
    }
}
