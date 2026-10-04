package com.calixsentry.detection;

import com.calixsentry.pipeline.RequestContext;

/**
 * Common contract for every detection module (signature-based or
 * behavioral). Implementations must be stateless w.r.t. a single request -
 * any cross-request state (e.g. per-client history) is looked up through an
 * injected collaborator such as ClientActivityTracker, never held as mutable
 * instance state keyed by request, to keep detectors thread-safe and testable
 * in isolation.
 *
 * Rules are metadata-described (rule id, category, severity, description) so
 * the dashboard and API can present them uniformly and so they can later be
 * toggled/edited without code changes.
 */
public interface Detector {

    /** Stable identifier, e.g. "CS-SQLI-001". */
    String ruleId();

    String name();

    DetectionCategory category();

    Severity severity();

    String description();

    boolean isEnabled();

    DetectionResult evaluate(RequestContext context);
}
