package com.calixsentry.policy;

import java.time.Duration;

/**
 * The Policy Engine's output: what CalixSentry will actually DO about a
 * request, as distinct from what was DETECTED. This is the detection/policy
 * separation required by spec section 2.
 */
public record PolicyDecision(
        Action action,
        Action recommendedAction,   // what MANUAL mode would suggest, even when action taken is only LOG/ALERT
        String explanation,
        Duration blockDuration      // populated only when action/recommendedAction implies a block
) {
    public static PolicyDecision allow() {
        return new PolicyDecision(Action.ALLOW, Action.ALLOW, "No suspicious activity detected", null);
    }
}
