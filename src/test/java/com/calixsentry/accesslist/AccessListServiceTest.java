package com.calixsentry.accesslist;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AccessListServiceTest {

    @Test
    void exactIpAllowlistMatches() {
        AccessListService service = new AccessListService();
        service.allow("192.168.1.50", "trusted office IP", "admin");
        assertTrue(service.isAllowlisted("192.168.1.50"));
        assertFalse(service.isAllowlisted("192.168.1.51"));
    }

    @Test
    void cidrDenylistMatchesWholeRange() {
        AccessListService service = new AccessListService();
        service.deny("203.0.113.0/24", "known malicious range", "admin");
        assertTrue(service.isDenylisted("203.0.113.77"));
        assertFalse(service.isDenylisted("203.0.114.1"));
    }

    @Test
    void testMatchPreviewsWithoutSavingAnything() {
        AccessListService service = new AccessListService();
        assertTrue(service.testMatch("10.0.0.5", "10.0.0.0/24"));
        assertTrue(service.list(AccessListEntry.ListType.ALLOW).isEmpty());
        assertTrue(service.list(AccessListEntry.ListType.DENY).isEmpty());
    }

    @Test
    void removeDeletesEntry() {
        AccessListService service = new AccessListService();
        service.allow("172.16.0.1", "test", "admin");
        assertTrue(service.remove("172.16.0.1", AccessListEntry.ListType.ALLOW));
        assertFalse(service.isAllowlisted("172.16.0.1"));
    }

    @Test
    void malformedEntryNeverSilentlyMatchesEverything() {
        AccessListService service = new AccessListService();
        service.allow("not-a-valid-cidr/999", "broken entry", "admin");
        assertFalse(service.isAllowlisted("8.8.8.8"));
    }
}
