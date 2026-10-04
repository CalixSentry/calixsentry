package com.calixsentry.blocking;

import com.calixsentry.config.CalixSentryProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryBlockStoreTest {

    private BlockStore newStore(Path tempDir) {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getTemporaryBlock().setPersistenceFile(tempDir.resolve("blocks.json").toString());
        return new InMemoryBlockStore(props);
    }

    @Test
    void temporaryBlockExpiresAutomatically(@TempDir Path tempDir) throws InterruptedException {
        InMemoryBlockStore store = (InMemoryBlockStore) newStore(tempDir);
        store.blockTemporary("1.2.3.4", "test", "CS-TEST", Duration.ofMillis(50), "SYSTEM");

        assertTrue(store.isBlocked("1.2.3.4"));
        Thread.sleep(150);
        store.purgeExpired();

        assertFalse(store.isBlocked("1.2.3.4"), "Block must automatically disappear once its duration elapses");
    }

    @Test
    void manualPermanentBlockNeverExpires(@TempDir Path tempDir) {
        BlockStore store = newStore(tempDir);
        store.blockPermanent("5.6.7.8", "manual admin block", "CS-MANUAL-BLOCK", "admin");
        store.purgeExpired();
        assertTrue(store.isBlocked("5.6.7.8"));
    }

    @Test
    void unblockRemovesActiveBlock(@TempDir Path tempDir) {
        BlockStore store = newStore(tempDir);
        store.blockTemporary("9.9.9.9", "test", "CS-TEST", Duration.ofMinutes(10), "SYSTEM");
        assertTrue(store.isBlocked("9.9.9.9"));

        assertTrue(store.unblock("9.9.9.9"));
        assertFalse(store.isBlocked("9.9.9.9"));
    }

    @Test
    void extendPushesExpiryFurtherOut(@TempDir Path tempDir) {
        BlockStore store = newStore(tempDir);
        BlockEntry entry = store.blockTemporary("2.2.2.2", "test", "CS-TEST", Duration.ofMinutes(5), "SYSTEM");
        var before = entry.getExpiresAt();

        var extended = store.extend("2.2.2.2", Duration.ofMinutes(30));
        assertTrue(extended.isPresent());
        assertTrue(extended.get().getExpiresAt().isAfter(before));
    }

    @Test
    void persistsAcrossRestart(@TempDir Path tempDir) {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getTemporaryBlock().setPersistenceFile(tempDir.resolve("blocks.json").toString());

        InMemoryBlockStore first = new InMemoryBlockStore(props);
        first.blockTemporary("3.3.3.3", "persisted", "CS-TEST", Duration.ofMinutes(10), "SYSTEM");

        // Simulate a restart: a brand new store instance loading from the same file.
        InMemoryBlockStore second = new InMemoryBlockStore(props);
        second.load();

        assertTrue(second.isBlocked("3.3.3.3"), "Active blocks must survive a CalixSentry restart");
    }
}
