package com.calixsentry.api;

import com.calixsentry.activity.IpActivityStore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * {basePath}/api/ips - the live, per-IP picture.
 *
 *   GET /ips           every tracked IP with totals (sortable in the dashboard)
 *   GET /ips/{ip}      one IP in full: paths it requested, status codes, recent request trail
 */
@RestController
@RequestMapping("${calixsentry.management.base-path}/api/ips")
public class IpController {

    private final IpActivityStore store;

    public IpController(IpActivityStore store) {
        this.store = store;
    }

    @GetMapping
    public List<IpActivityStore.IpSummary> list(@RequestParam(defaultValue = "500") int limit,
                                                 @RequestParam(required = false) String q) {
        return store.summaries(q, Math.min(limit, 5000));
    }

    @GetMapping("/{ip}")
    public ResponseEntity<IpActivityStore.IpProfile> profile(@PathVariable String ip) {
        return store.profile(ip).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }
}
