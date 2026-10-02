package com.calixsentry.logs;

/** The two kinds of daily log CalixSentry writes. */
public enum LogKind {
    /** Security events: detections, blocks, rate limits. */
    EVENTS("calixsentry-events"),
    /** Every proxied request (who asked for what, and what happened). */
    ACCESS("calixsentry-access");

    private final String filePrefix;

    LogKind(String filePrefix) {
        this.filePrefix = filePrefix;
    }

    public String filePrefix() {
        return filePrefix;
    }

    /** Parses the URL form ("events" / "access"); returns null if unknown. */
    public static LogKind fromUrlName(String name) {
        if (name == null) return null;
        return switch (name.toLowerCase()) {
            case "events" -> EVENTS;
            case "access" -> ACCESS;
            default -> null;
        };
    }
}
