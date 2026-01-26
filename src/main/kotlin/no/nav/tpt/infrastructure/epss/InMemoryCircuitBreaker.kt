package no.nav.tpt.infrastructure.epss

import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class InMemoryCircuitBreaker(
    private val failureThreshold: Int = 3,
    private val openDurationSeconds: Long = 300
) : CircuitBreaker {
    private val failureCount = AtomicInteger(0)
    private val openedAt = AtomicReference<Instant?>(null)

    override suspend fun isOpen(): Boolean {
        val openTime = openedAt.get() ?: return false
        val elapsed = Instant.now().epochSecond - openTime.epochSecond
        
        if (elapsed >= openDurationSeconds) {
            reset()
            return false
        }
        
        return true
    }

    override suspend fun recordSuccess() {
        failureCount.set(0)
        openedAt.set(null)
    }

    override suspend fun recordFailure() {
        val failures = failureCount.incrementAndGet()
        if (failures >= failureThreshold) {
            openedAt.set(Instant.now())
        }
    }

    private fun reset() {
        failureCount.set(0)
        openedAt.set(null)
    }
}
