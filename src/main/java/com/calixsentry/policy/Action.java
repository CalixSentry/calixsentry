package com.calixsentry.policy;

public enum Action {
    ALLOW,
    LOG,
    ALERT,
    RATE_LIMIT,
    TEMPORARY_BLOCK,
    BLOCK
}
