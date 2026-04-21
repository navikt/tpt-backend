package no.nav.tpt.util

import kotlinx.coroutines.delay

suspend fun <T> withRetry(
    maxAttempts: Int = 3,
    initialDelayMs: Long = 1000,
    block: suspend () -> T
): T {
    var delayMs = initialDelayMs
    repeat(maxAttempts - 1) { attempt ->
        try {
            return block()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            delay(delayMs)
            delayMs *= 2
        }
    }
    return block()
}
