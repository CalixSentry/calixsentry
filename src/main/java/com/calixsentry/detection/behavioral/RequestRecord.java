package com.calixsentry.detection.behavioral;

import java.time.Instant;

/**
 * One entry in a client's rolling activity window. Mutable `status` field is
 * intentional: the record is created BEFORE the backend responds (so rate/interval
 * stats are available pre-response) and updated with the actual status AFTER
 * the backend responds (so 404/403/5xx ratios reflect reality).
 */
public final class RequestRecord {
    final Instant timestamp;
    final String path;
    final String method;
    final String userAgent;
    volatile int status = -1; // -1 = pending, backend has not responded yet

    RequestRecord(Instant timestamp, String path, String method, String userAgent) {
        this.timestamp = timestamp;
        this.path = path;
        this.method = method;
        this.userAgent = userAgent;
    }

    public void setStatus(int status) {
        this.status = status;
    }
}
