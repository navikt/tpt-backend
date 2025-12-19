package no.nav.tpt.infrastructure.nvd

import kotlinx.coroutines.Dispatchers
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.Transaction
import org.jetbrains.exposed.sql.transactions.experimental.newSuspendedTransaction
import org.slf4j.LoggerFactory

class NvdSyncLeaderElection(private val database: Database) {
    private val logger = LoggerFactory.getLogger(NvdSyncLeaderElection::class.java)

    // PostgreSQL advisory lock key for NVD sync
    // Using a fixed number to identify NVD sync operations across all pods
    private val NVD_SYNC_LOCK_KEY = 7463823L // "tpt" as numbers on phone keypad

    suspend fun <T> withLeaderLock(operation: suspend () -> T): T? {
        return newSuspendedTransaction(Dispatchers.IO, database) {
            // Try to acquire advisory lock (non-blocking)
            val lockAcquired = tryAcquireLock()

            if (!lockAcquired) {
                logger.info("Could not acquire NVD sync lock - another pod is already syncing")
                return@newSuspendedTransaction null
            }

            try {
                logger.info("Acquired NVD sync lock - this pod will perform the sync")
                operation()
            } finally {
                releaseLock()
                logger.info("Released NVD sync lock")
            }
        }
    }

    private fun Transaction.tryAcquireLock(): Boolean {
        return exec("SELECT pg_try_advisory_lock($NVD_SYNC_LOCK_KEY)") { rs ->
            if (rs.next()) rs.getBoolean(1) else false
        } ?: false
    }

    private fun Transaction.releaseLock() {
        exec("SELECT pg_advisory_unlock($NVD_SYNC_LOCK_KEY)") { }
    }
}

