package no.nav.tpt.infrastructure.kafka

import kotlinx.coroutines.delay
import java.time.Duration

val TEST_POLL_TIMEOUT: Duration = Duration.ofMillis(100)

/**
 * Polls [condition] every [intervalMs] milliseconds until it returns true or [timeoutMs] elapses.
 * Throws [AssertionError] with [message] on timeout.
 */
suspend fun awaitCondition(
    timeoutMs: Long = 5000,
    intervalMs: Long = 100,
    message: String = "Condition not met within ${timeoutMs}ms",
    condition: suspend () -> Boolean,
) {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        if (condition()) return
        delay(intervalMs)
    }
    if (!condition()) error(message)
}
