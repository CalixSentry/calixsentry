package com.calixsentry.api;

import com.calixsentry.accesslist.AccessListEntry;
import com.calixsentry.accesslist.AccessListService;
import jakarta.validation.constraints.NotBlank;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/** {basePath}/api/allowlist and /denylist (spec sections 14, 15). */
@RestController
@RequestMapping("${calixsentry.management.base-path}/api")
public class AccessListController {

    private final AccessListService service;

    public AccessListController(AccessListService service) {
        this.service = service;
    }

    public record EntryRequest(@NotBlank String value, @NotBlank String reason) {}
    public record TestRequest(@NotBlank String candidateIp, @NotBlank String cidrOrIp) {}

    @GetMapping("/allowlist")
    public List<AccessListEntry> allowlist() { return service.list(AccessListEntry.ListType.ALLOW); }

    @PostMapping("/allowlist")
    public AccessListEntry addAllow(@RequestBody EntryRequest req, @AuthenticationPrincipal UserDetails user) {
        return service.allow(req.value(), req.reason(), user != null ? user.getUsername() : "admin");
    }

    /** Value goes in the query string: a CIDR like 10.0.0.0/24 contains a '/', which cannot live in a URL path segment. */
    @DeleteMapping("/allowlist")
    public Map<String, Boolean> removeAllow(@RequestParam String value) {
        return Map.of("removed", service.remove(value, AccessListEntry.ListType.ALLOW));
    }

    @GetMapping("/denylist")
    public List<AccessListEntry> denylist() { return service.list(AccessListEntry.ListType.DENY); }

    @PostMapping("/denylist")
    public AccessListEntry addDeny(@RequestBody EntryRequest req, @AuthenticationPrincipal UserDetails user) {
        return service.deny(req.value(), req.reason(), user != null ? user.getUsername() : "admin");
    }

    @DeleteMapping("/denylist")
    public Map<String, Boolean> removeDeny(@RequestParam String value) {
        return Map.of("removed", service.remove(value, AccessListEntry.ListType.DENY));
    }

    /** Preview a rule before applying it (spec section 15: "preview/test rules before applying them"). */
    @PostMapping("/access-list/test")
    public Map<String, Boolean> test(@RequestBody TestRequest req) {
        return Map.of("matches", service.testMatch(req.candidateIp(), req.cidrOrIp()));
    }
}
