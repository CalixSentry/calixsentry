package com.calixsentry.events;

/**
 * Extension point for where security events are delivered. See spec section
 * 11: JSON / local file / syslog / webhook / Elasticsearch. Implementations
 * must never throw out of publish() - a failing sink must not break the
 * request pipeline.
 */
public interface EventSink {
    void publish(SecurityEvent event);
    boolean isEnabled();
    String name();
}
