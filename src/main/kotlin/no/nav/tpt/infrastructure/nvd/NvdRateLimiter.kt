package no.nav.tpt.infrastructure.nvd

import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Enforces a minimum interval between requests to the NVD API. Intended to be shared by a
 * single [NvdClient] instance across all its callers (scheduled sync jobs, single-CVE lookups,
 * admin-triggered backfills), so that the whole application respects NVD's published rate
 * limits regardless of how many logical callers exist.
 *
 * NVD's public rate limits (see https://nvd.nist.gov/developers/start-here):
 * - Without an API key: 5 requests / 30 seconds
 * - With an API key: 50 requests / 30 seconds
 */
class NvdRateLimiter(
    val minIntervalMs: Long,
    private val nowMillis: () -> Long = System::currentTimeMillis,
) {
    private val mutex = Mutex()
    private var lastRequestAtMillis: Long? = null

    suspend fun acquire() {
        mutex.withLock {
            val last = lastRequestAtMillis
            if (last != null) {
                val elapsed = nowMillis() - last
                val waitMs = minIntervalMs - elapsed
                if (waitMs > 0) {
                    delay(waitMs)
                }
            }
            lastRequestAtMillis = nowMillis()
        }
    }

    companion object {
        const val NO_API_KEY_INTERVAL_MS = 6000L
        const val WITH_API_KEY_INTERVAL_MS = 600L

        fun forApiKey(apiKey: String?): NvdRateLimiter =
            NvdRateLimiter(if (apiKey != null) WITH_API_KEY_INTERVAL_MS else NO_API_KEY_INTERVAL_MS)
    }
}
