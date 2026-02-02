package no.nav.tpt.infrastructure.admin

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Duration
import java.time.Instant

/**
 * Simple in-memory cache for admin reports with TTL support.
 * Thread-safe using Mutex for concurrent access.
 */
class AdminReportCache<T>(
    private val ttl: Duration = Duration.ofMinutes(30)
) {
    private var cachedValue: T? = null
    private var cachedAt: Instant? = null
    private val mutex = Mutex()

    suspend fun get(supplier: suspend () -> T): T = mutex.withLock {
        val now = Instant.now()
        val cached = cachedValue
        val timestamp = cachedAt

        if (cached != null && timestamp != null && Duration.between(timestamp, now) < ttl) {
            return@withLock cached
        }

        val fresh = supplier()
        cachedValue = fresh
        cachedAt = now
        return@withLock fresh
    }

    suspend fun invalidate() = mutex.withLock {
        cachedValue = null
        cachedAt = null
    }
}
