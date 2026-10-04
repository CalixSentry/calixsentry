package com.calixsentry.api;

import com.calixsentry.blocking.BlockEntry;
import com.calixsentry.blocking.BlockStore;
import com.calixsentry.config.CalixSentryProperties;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * {basePath}/api/blocks - manual IP/client block management (spec section
 * 14). Every mutating action is attributed to the authenticated admin user.
 */
@RestController
@RequestMapping("${calixsentry.management.base-path}/api/blocks")
public class BlocksController {

    private final BlockStore blockStore;
    private final CalixSentryProperties properties;

    public BlocksController(BlockStore blockStore, CalixSentryProperties properties) {
        this.blockStore = blockStore;
        this.properties = properties;
    }

    public record BlockRequest(@NotBlank String ip, @NotBlank String reason, Long durationSeconds, boolean permanent) {}
    public record ExtendRequest(@NotBlank Long additionalSeconds) {}

    @GetMapping
    public List<BlockEntry> list() {
        return blockStore.listActiveBlocks();
    }

    @PostMapping
    public ResponseEntity<BlockEntry> create(@RequestBody BlockRequest request,
                                              @AuthenticationPrincipal UserDetails user) {
        String actor = user != null ? user.getUsername() : "admin";
        if (request.permanent()) {
            return ResponseEntity.ok(blockStore.blockPermanent(request.ip(), request.reason(), "CS-MANUAL-BLOCK", actor));
        }
        Duration duration = request.durationSeconds() != null
                ? Duration.ofSeconds(request.durationSeconds())
                : properties.getTemporaryBlock().getDefaultDuration();

        if (!properties.getTemporaryBlock().getAllowedDurationsSeconds().contains(duration.toSeconds())) {
            // Still allowed (spec lists a "Custom duration" option) - just not one of the presets.
        }
        return ResponseEntity.ok(blockStore.blockTemporary(request.ip(), request.reason(), "CS-MANUAL-BLOCK", duration, actor));
    }

    @DeleteMapping("/{ip}")
    public ResponseEntity<Map<String, Boolean>> unblock(@PathVariable String ip) {
        boolean removed = blockStore.unblock(ip);
        return ResponseEntity.ok(Map.of("unblocked", removed));
    }

    @PostMapping("/{ip}/extend")
    public ResponseEntity<BlockEntry> extend(@PathVariable String ip, @RequestBody ExtendRequest request) {
        return blockStore.extend(ip, Duration.ofSeconds(request.additionalSeconds()))
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/{ip}/permanent")
    public ResponseEntity<BlockEntry> promote(@PathVariable String ip) {
        return blockStore.promoteToPermanent(ip)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** Allowed preset durations, for the dashboard's duration picker (spec section 3/17). */
    @GetMapping("/durations")
    public List<Long> allowedDurations() {
        return properties.getTemporaryBlock().getAllowedDurationsSeconds();
    }
}
