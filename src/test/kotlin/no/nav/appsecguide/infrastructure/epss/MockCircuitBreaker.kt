package no.nav.appsecguide.infrastructure.epss

class MockCircuitBreaker(
    private var open: Boolean = false
) : CircuitBreaker {
    override suspend fun isOpen(): Boolean = open

    override suspend fun recordFailure() {
        open = true
    }

    override suspend fun recordSuccess() {
        open = false
    }

    fun setOpen(value: Boolean) {
        open = value
    }
}

