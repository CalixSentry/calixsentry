package com.calixsentry.policy;

/**
 * See spec section 3. MONITOR is the only mode considered "safe by default"
 * (spec section 18) - it is what a fresh install ships with.
 */
public enum ProtectionMode {
    /** Detect and record. Never blocks, regardless of score. */
    MONITOR,
    /** Detect and raise alerts above a threshold. Never blocks. */
    ALERT,
    /** Detect, raise alerts, and surface a RECOMMENDED action for an administrator to apply manually. Never auto-blocks. */
    MANUAL,
    /** Detect and, ONLY if protection.automaticBlocking=true, apply temporary blocks automatically when thresholds are met. */
    AUTOMATIC
}
