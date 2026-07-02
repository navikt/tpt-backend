package no.nav.tpt.infrastructure.nvd

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.currentTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class NvdRateLimiterTest {

    @Test
    fun `should not delay the first acquire`() = runTest {
        val limiter = NvdRateLimiter(minIntervalMs = 6000, nowMillis = { currentTime })

        limiter.acquire()

        assertEquals(0, currentTime)
    }

    @Test
    fun `should delay second acquire until minimum interval has passed`() = runTest {
        val limiter = NvdRateLimiter(minIntervalMs = 6000, nowMillis = { currentTime })

        limiter.acquire()
        limiter.acquire()

        assertTrue(currentTime >= 6000)
    }

    @Test
    fun `should not add extra delay when enough time has already passed`() = runTest {
        val limiter = NvdRateLimiter(minIntervalMs = 6000, nowMillis = { currentTime })

        limiter.acquire()
        kotlinx.coroutines.delay(10_000)
        val beforeSecondAcquire = currentTime

        limiter.acquire()

        assertEquals(beforeSecondAcquire, currentTime)
    }

    @Test
    fun `should enforce interval across three sequential calls`() = runTest {
        val limiter = NvdRateLimiter(minIntervalMs = 1000, nowMillis = { currentTime })

        limiter.acquire()
        limiter.acquire()
        limiter.acquire()

        assertTrue(currentTime >= 2000)
    }

    @Test
    fun `forApiKey should use the faster interval when an api key is provided`() {
        val limiter = NvdRateLimiter.forApiKey("some-key")

        assertEquals(NvdRateLimiter.WITH_API_KEY_INTERVAL_MS, limiter.minIntervalMs)
    }

    @Test
    fun `forApiKey should use the conservative interval when no api key is provided`() {
        val limiter = NvdRateLimiter.forApiKey(null)

        assertEquals(NvdRateLimiter.NO_API_KEY_INTERVAL_MS, limiter.minIntervalMs)
    }
}
