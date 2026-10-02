package com.calixsentry;

import com.calixsentry.config.CalixSentryProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * CalixSentry Engine + Gateway (MVP consolidated deployment).
 *
 * <p>In this MVP, the "Gateway" (reverse proxy) and the "Engine" (detection,
 * scoring, policy) run inside a single Spring Boot process. See
 * docs/ARCHITECTURE.md for the reasoning and the future-state split into a
 * dedicated edge proxy (nginx/Envoy) calling out to this engine as a decision
 * service.
 */
@SpringBootApplication
@EnableConfigurationProperties(CalixSentryProperties.class)
@EnableScheduling
public class CalixSentryApplication {

    public static void main(String[] args) {
        SpringApplication.run(CalixSentryApplication.class, args);
    }
}
