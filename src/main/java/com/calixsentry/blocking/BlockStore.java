package com.calixsentry.blocking;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Manages IP/client blocks: temporary (auto-expiring) and permanent.
 *
 * Interface exists so the MVP's file-backed InMemoryBlockStore can later be
 * swapped for a database or distributed store (Redis, etc.) for multi-node
 * deployments without touching the gateway/policy code.
 */
public interface BlockStore {

    BlockEntry blockTemporary(String ip, String reason, String ruleId, Duration duration, String createdBy);

    BlockEntry blockPermanent(String ip, String reason, String ruleId, String createdBy);

    boolean unblock(String ip);

    Optional<BlockEntry> extend(String ip, Duration additionalDuration);

    Optional<BlockEntry> promoteToPermanent(String ip);

    /** Returns the active block for this IP, if any (expired blocks never returned). */
    Optional<BlockEntry> findActiveBlock(String ip);

    boolean isBlocked(String ip);

    List<BlockEntry> listActiveBlocks();

    /** Removes expired temporary blocks. Called on a schedule; also checked lazily on lookup. */
    void purgeExpired();
}
