package com.calixsentry.gateway;

import java.util.Map;

public record BackendResponse(int status, Map<String, java.util.List<String>> headers, byte[] body) {
}
