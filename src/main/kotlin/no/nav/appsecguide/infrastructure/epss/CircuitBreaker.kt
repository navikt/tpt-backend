package no.nav.appsecguide.infrastructure.epss

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import java.time.Instant

interface CircuitBreaker {
    suspend fun isOpen(): Boolean
    suspend fun recordFailure()
    suspend fun recordSuccess()
}

class ValkeyCircuitBreaker(
    private val pool: io.valkey.JedisPool,
    private val keyPrefix: String,
    private val openDurationSeconds: Long = 24 * 60 * 60 // 24 hours
) : CircuitBreaker {
    private val logger = LoggerFactory.getLogger(ValkeyCircuitBreaker::class.java)
    private val circuitKey = "$keyPrefix:circuit-breaker"

    override suspend fun isOpen(): Boolean = withContext(Dispatchers.IO) {
        try {
            pool.resource.use { client ->
                val value = client.get(circuitKey)
                if (value != null) {
                    val openUntil = value.toLongOrNull() ?: return@withContext false
                    val now = Instant.now().epochSecond
                    if (now < openUntil) {
                        val remainingHours = (openUntil - now) / 3600
                        logger.debug("Circuit breaker is OPEN. Reopens in ~$remainingHours hours")
                        return@withContext true
                    } else {
                        // Expired, clean up
                        client.del(circuitKey)
                        logger.info("Circuit breaker expired and reset to CLOSED")
                    }
                }
                false
            }
        } catch (e: Exception) {
            logger.error("Failed to check circuit breaker state, defaulting to CLOSED", e)
            false
        }
    }

    override suspend fun recordFailure(): Unit = withContext(Dispatchers.IO) {
        try {
            pool.resource.use { client ->
                val openUntil = Instant.now().epochSecond + openDurationSeconds
                client.setex(circuitKey, openDurationSeconds, openUntil.toString())
                logger.error("Circuit breaker OPENED due to rate limit. Will retry after 24 hours")
            }
        } catch (e: Exception) {
            logger.error("Failed to open circuit breaker", e)
        }
    }

    override suspend fun recordSuccess(): Unit = withContext(Dispatchers.IO) {
        try {
            pool.resource.use { client ->
                val wasOpen = client.get(circuitKey) != null
                if (wasOpen) {
                    client.del(circuitKey)
                    logger.info("Circuit breaker reset to CLOSED after successful API call")
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to record success in circuit breaker", e)
        }
    }
}

