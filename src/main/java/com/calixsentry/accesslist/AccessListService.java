package com.calixsentry.accesslist;

import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * IP/CIDR allowlist and denylist. Allowlisted clients bypass detection-driven
 * actions (they are still logged, per spec section 15's spirit of no silent
 * dangerous behaviour); denylisted clients are blocked outright, equivalent
 * to a permanent manual block.
 *
 * Per spec section 15: "Allow administrators to preview/test rules before
 * applying them" - see {@link #testMatch(String)}, usable by the API before
 * committing an entry.
 */
@Component
public class AccessListService {

    private final CopyOnWriteArrayList<AccessListEntry> entries = new CopyOnWriteArrayList<>();

    public AccessListEntry allow(String value, String reason, String createdBy) {
        AccessListEntry entry = build(value, AccessListEntry.ListType.ALLOW, reason, createdBy);
        entries.add(entry);
        return entry;
    }

    public AccessListEntry deny(String value, String reason, String createdBy) {
        AccessListEntry entry = build(value, AccessListEntry.ListType.DENY, reason, createdBy);
        entries.add(entry);
        return entry;
    }

    public boolean remove(String value, AccessListEntry.ListType listType) {
        return entries.removeIf(e -> e.getValue().equals(value) && e.getListType() == listType);
    }

    public boolean isAllowlisted(String ip) {
        return matches(ip, AccessListEntry.ListType.ALLOW);
    }

    public boolean isDenylisted(String ip) {
        return matches(ip, AccessListEntry.ListType.DENY);
    }

    public List<AccessListEntry> list(AccessListEntry.ListType listType) {
        return entries.stream().filter(e -> e.getListType() == listType).toList();
    }

    /** Preview whether a candidate IP would match a given CIDR/IP value, without saving anything. */
    public boolean testMatch(String candidateIp, String cidrOrIp) {
        return matchesValue(candidateIp, cidrOrIp);
    }

    private boolean matches(String ip, AccessListEntry.ListType listType) {
        for (AccessListEntry entry : entries) {
            if (entry.getListType() == listType && matchesValue(ip, entry.getValue())) {
                return true;
            }
        }
        return false;
    }

    private AccessListEntry build(String value, AccessListEntry.ListType listType, String reason, String createdBy) {
        AccessListEntry.MatchType matchType = value.contains("/")
                ? AccessListEntry.MatchType.CIDR
                : AccessListEntry.MatchType.IP;
        return new AccessListEntry(value, listType, matchType, reason, createdBy, Instant.now());
    }

    private boolean matchesValue(String ip, String value) {
        try {
            if (value.contains("/")) {
                return cidrContains(value, ip);
            }
            return value.equals(ip);
        } catch (Exception e) {
            return false; // malformed entries never silently match everything
        }
    }

    private boolean cidrContains(String cidr, String ip) throws UnknownHostException {
        String[] parts = cidr.split("/");
        InetAddress cidrAddr = InetAddress.getByName(parts[0]);
        int prefixLength = Integer.parseInt(parts[1]);
        InetAddress targetAddr = InetAddress.getByName(ip);

        if (cidrAddr.getAddress().length != targetAddr.getAddress().length) {
            return false; // IPv4 vs IPv6 mismatch
        }

        BigInteger cidrInt = new BigInteger(1, cidrAddr.getAddress());
        BigInteger targetInt = new BigInteger(1, targetAddr.getAddress());
        int addressBits = cidrAddr.getAddress().length * 8;
        BigInteger mask = BigInteger.valueOf(-1).shiftLeft(addressBits - prefixLength);

        return cidrInt.and(mask).equals(targetInt.and(mask));
    }
}
