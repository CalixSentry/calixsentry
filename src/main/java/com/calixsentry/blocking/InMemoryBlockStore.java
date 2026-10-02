package com.calixsentry.blocking;

import com.calixsentry.config.CalixSentryProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * MVP block store: in-memory map of active blocks, persisted to a JSON file
 * on every mutation so a CalixSentry restart does not silently lose active
 * blocks (spec section 17: "Persist them appropriately").
 *
 * NOTE (honesty per spec section 35): this is single-node, file-based
 * persistence, not a database. It is adequate for a single-instance MVP
 * deployment. A multi-node/production deployment needs a shared store - see
 * docs/ROADMAP.md.
 */
@Component
public class InMemoryBlockStore implements BlockStore {

    private static final Logger log = LoggerFactory.getLogger(InMemoryBlockStore.class);

    private final ConcurrentHashMap<String, BlockEntry> blocks = new ConcurrentHashMap<>();
    private final CalixSentryProperties properties;
    private final ObjectMapper objectMapper;

    public InMemoryBlockStore(CalixSentryProperties properties) {
        this.properties = properties;
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @PostConstruct
    void load() {
        File file = new File(properties.getTemporaryBlock().getPersistenceFile());
        if (!file.exists()) return;
        try {
            List<BlockEntry> loaded = objectMapper.readValue(file,
                    objectMapper.getTypeFactory().constructCollectionType(List.class, BlockEntry.class));
            for (BlockEntry entry : loaded) {
                if (!entry.isExpired()) {
                    blocks.put(entry.getIp(), entry);
                }
            }
            log.info("Loaded {} active block(s) from {}", blocks.size(), file.getAbsolutePath());
        } catch (IOException e) {
            log.warn("Could not load persisted blocks from {}: {}", file.getAbsolutePath(), e.getMessage());
        }
    }

    private synchronized void persist() {
        File file = new File(properties.getTemporaryBlock().getPersistenceFile());
        try {
            File parent = file.getParentFile();
            if (parent != null) parent.mkdirs();
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(file, List.copyOf(blocks.values()));
        } catch (IOException e) {
            log.error("Failed to persist block store to {}: {}", file.getAbsolutePath(), e.getMessage());
        }
    }

    @Override
    public BlockEntry blockTemporary(String ip, String reason, String ruleId, Duration duration, String createdBy) {
        Instant now = Instant.now();
        BlockEntry entry = new BlockEntry(ip, reason, ruleId, BlockType.TEMPORARY, createdBy, now, now.plus(duration));
        blocks.put(ip, entry);
        persist();
        log.info("BLOCK (temporary) ip={} duration={} reason=\"{}\" by={}", ip, duration, reason, createdBy);
        return entry;
    }

    @Override
    public BlockEntry blockPermanent(String ip, String reason, String ruleId, String createdBy) {
        Instant now = Instant.now();
        BlockEntry entry = new BlockEntry(ip, reason, ruleId, BlockType.PERMANENT, createdBy, now, null);
        blocks.put(ip, entry);
        persist();
        log.info("BLOCK (permanent) ip={} reason=\"{}\" by={}", ip, reason, createdBy);
        return entry;
    }

    @Override
    public boolean unblock(String ip) {
        BlockEntry removed = blocks.remove(ip);
        if (removed != null) {
            persist();
            log.info("UNBLOCK ip={}", ip);
            return true;
        }
        return false;
    }

    @Override
    public Optional<BlockEntry> extend(String ip, Duration additionalDuration) {
        BlockEntry entry = blocks.get(ip);
        if (entry == null || entry.isExpired()) return Optional.empty();
        if (entry.getType() == BlockType.TEMPORARY) {
            Instant base = entry.getExpiresAt() != null ? entry.getExpiresAt() : Instant.now();
            entry.setExpiresAt(base.plus(additionalDuration));
            persist();
            log.info("EXTEND block ip={} newExpiry={}", ip, entry.getExpiresAt());
        }
        return Optional.of(entry);
    }

    @Override
    public Optional<BlockEntry> promoteToPermanent(String ip) {
        BlockEntry entry = blocks.get(ip);
        if (entry == null) return Optional.empty();
        entry.setType(BlockType.PERMANENT);
        entry.setExpiresAt(null);
        persist();
        log.info("PROMOTE ip={} to PERMANENT", ip);
        return Optional.of(entry);
    }

    @Override
    public Optional<BlockEntry> findActiveBlock(String ip) {
        BlockEntry entry = blocks.get(ip);
        if (entry == null) return Optional.empty();
        if (entry.isExpired()) {
            blocks.remove(ip, entry);
            persist();
            return Optional.empty();
        }
        return Optional.of(entry);
    }

    @Override
    public boolean isBlocked(String ip) {
        return findActiveBlock(ip).isPresent();
    }

    @Override
    public List<BlockEntry> listActiveBlocks() {
        purgeExpired();
        return List.copyOf(blocks.values());
    }

    @Override
    public void purgeExpired() {
        boolean changed = false;
        for (BlockEntry entry : blocks.values()) {
            if (entry.isExpired()) {
                blocks.remove(entry.getIp(), entry);
                changed = true;
                log.info("Temporary block EXPIRED ip={}", entry.getIp());
            }
        }
        if (changed) persist();
    }

    /** Automatic expiry sweep - spec section 17: "Do not require manual cleanup." */
    @Scheduled(fixedDelay = 15_000)
    public void scheduledPurge() {
        purgeExpired();
    }
}
