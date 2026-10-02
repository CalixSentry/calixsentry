package com.calixsentry.detection;

/**
 * A single piece of evidence contributed by a detector, e.g.
 * "94% of requests returned 404" or "SQL injection pattern in query string".
 * Findings are what the dashboard's "Why was this detected?" view is built from.
 */
public record Finding(String reasonText, int scoreContribution) {
}
