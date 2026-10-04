package com.calixsentry.events.sinks;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.events.EventSink;
import com.calixsentry.events.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 * Posts each event as JSON to a configured webhook URL (Slack/Teams/generic
 * SIEM webhook receivers, etc.). Disabled by default. Failures are logged
 * and swallowed - a webhook outage must never impact request handling.
 */
@Component
public class WebhookEventSink implements EventSink {

    private static final Logger log = LoggerFactory.getLogger(WebhookEventSink.class);
    private final CalixSentryProperties properties;
    private final RestTemplate restTemplate = new RestTemplate();

    public WebhookEventSink(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Override
    public void publish(SecurityEvent event) {
        if (!isEnabled()) return;
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            restTemplate.postForEntity(properties.getEvents().getWebhookUrl(),
                    new HttpEntity<>(event, headers), Void.class);
        } catch (Exception e) {
            log.warn("WebhookEventSink delivery failed: {}", e.getMessage());
        }
    }

    @Override public boolean isEnabled() {
        return properties.getEvents().isWebhookEnabled() && !properties.getEvents().getWebhookUrl().isBlank();
    }
    @Override public String name() { return "webhook"; }
}
