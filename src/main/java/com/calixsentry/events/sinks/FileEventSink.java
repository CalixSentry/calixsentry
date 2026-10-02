package com.calixsentry.events.sinks;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.events.EventSink;
import com.calixsentry.events.SecurityEvent;
import com.calixsentry.logs.DailyLogService;
import com.calixsentry.logs.LogKind;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Writes each security event as one JSON line into today's date-named file
 * (calixsentry-events-YYYY-MM-DD.jsonl) via {@link DailyLogService}.
 */
@Component
public class FileEventSink implements EventSink {

    private static final Logger log = LoggerFactory.getLogger(FileEventSink.class);

    private final CalixSentryProperties properties;
    private final DailyLogService dailyLogs;
    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    public FileEventSink(CalixSentryProperties properties, DailyLogService dailyLogs) {
        this.properties = properties;
        this.dailyLogs = dailyLogs;
    }

    @Override
    public void publish(SecurityEvent event) {
        if (!isEnabled()) return;
        try {
            dailyLogs.append(LogKind.EVENTS, mapper.writeValueAsString(event));
        } catch (Exception e) {
            log.error("FileEventSink failed to serialize event {}: {}", event.getId(), e.getMessage());
        }
    }

    @Override public boolean isEnabled() { return properties.getEvents().isFileSinkEnabled(); }
    @Override public String name() { return "file (daily)"; }
}
