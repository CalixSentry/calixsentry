package com.calixsentry.events.sinks;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.events.EventSink;
import com.calixsentry.events.SecurityEvent;
import org.springframework.stereotype.Component;

/**
 * NOT IMPLEMENTED (spec section 35 - labeled explicitly rather than faked).
 *
 * Elasticsearch integration is designed as OPTIONAL (spec section 29) and
 * this class exists as the extension point + config surface
 * (calixsentry.elasticsearch.*), but shipping a real client integration
 * (bulk indexing, ILM-friendly index naming, auth, TLS) is out of scope for
 * this MVP stage. Enabling `elasticsearch.enabled=true` currently does
 * nothing except make that fact visible via isEnabled()/name() in the
 * dashboard/API, so an administrator is never misled into thinking events
 * are being shipped when they are not.
 *
 * FUTURE FEATURE: implement using the official Elasticsearch Java client,
 * with bulk buffering and backpressure so a slow/unavailable cluster cannot
 * block the request pipeline.
 */
@Component
public class ElasticsearchEventSink implements EventSink {

    private final CalixSentryProperties properties;

    public ElasticsearchEventSink(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Override
    public void publish(SecurityEvent event) {
        // Intentionally a no-op. See class Javadoc: NOT IMPLEMENTED.
    }

    @Override public boolean isEnabled() { return false; } // always false until implemented, regardless of config
    @Override public String name() { return "elasticsearch (NOT IMPLEMENTED)"; }

    public boolean isConfiguredButUnimplemented() {
        return properties.getElasticsearch().isEnabled();
    }
}
