package no.nav.tpt.infrastructure.epss

interface CircuitBreaker {
    suspend fun isOpen(): Boolean
    suspend fun recordFailure()
    suspend fun recordSuccess()
}